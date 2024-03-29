mapping(int:function) services=([53|HOGAN_DNS:dns]);

//TODO: Cope adequately with all arrangements of incoming and outgoing TCP.
Protocols.DNS.async_dual_client upstream = Protocols.DNS.async_dual_client();
Stdio.File log = Stdio.File("dnsrequests.log", "wac");
object sharehosts = compile_file("sharehosts.pike")();

//Convert an IP address to a name from /etc/hosts - somewhat like a reverse DNS
//lookup, but won't go out over the internet. Also, unusually, returns the *last*
//name, not the first, because of how I have my hosts file set up. This is for
//logs only, not for actual PTR resolution.
string ip_to_host(string ip)
{
	//Lifted from sharehosts.pike
	foreach (Stdio.read_file("/etc/hosts")/"\n",string line)
	{
		sscanf(line,"%s#",line); line=String.normalize_space(line);
		array parts=lower_case(line)/" ";
		if (sizeof(parts)<2) continue; //Ignore this line - probably blank
		if (parts[0] == ip) return ip + "/" + parts[-1]; //Use parts[1] instead to return the canonical name
	}
	return ip;
}

mapping(int:string) dns_types = ([]);

//Return the key in G->G->dns_cache for the given string and type. Guaranteed stable;
//if its definition is ever changed, be sure that no previous key can be misinterpreted.
string cachekey(string name, int type)
{
	return sprintf("%s/%s", name, dns_types[type] || (string)type);
}

void respond(string name, mapping info, function(mapping:void) cb, array cnames)
{
	//Cache upstream's queries (based on TTLs) and pass the results downstream
	//Cache can be stored in G->G so it's retained across SIGHUP, but needn't be
	//retained on disk or anything.
	//For the moment, we cache only those requests which succeed.
	//Note that we also do not cache negative responses (eg "you requested an A
	//record for this name but none were returned"). They will be retried every
	//time they are requested.
	if (!info || info->rcode) {cb(info); return;}
	if (sizeof(cnames))
	{
		//Synthesize a request partly from the cache and partly from the
		//new response. WARNING: This can actually violate TTLs slightly.
		//If the upstream query takes several seconds, the CNAME records
		//from the cache will be returned as per the *start* of the query,
		//not the end. But honestly, I don't know what else I can do - what
		//if they've expired by the time I do the next query? Do I have to
		//discard what I have and start over?
		//One option would be to just populate the cache, then retrigger
		//the query. Would that work? It would potentially mean an infinite
		//loop with a degenerate authoritative server that sends a CNAME
		//with a TTL of 86400, pointing to a CNAME with a TTL of 1, pointing
		//to a remote A record. We would cache the first CNAME, then get
		//stuck looking up the A record, finding that the second CNAME is now
		//stale, starting over, using the cached CNAME, rinse and repeat.
		cb((["an": cnames + info->an]));
	}
	else
	{
		//Send the upstream request back downstream, unchanged.
		cb(info);
	}
	//Cacheable records can be in the ANSWER or ADDITIONAL section. We never cache
	//the AUTHORITY.
	array cacheme = info->an + info->ar;
	//Each cache key consists of the object name (in lower-case) and the record type.
	//CNAME trumps everything else, but otherwise, a RR is specific to its type.
	//When synthesizing responses, additional records MAY be included.
	mapping(string:array(mapping(string:string|int))) cache = ([]);
	//Whenever we receive from upstream a record for a particular name+type, we throw
	//away all previously-cached entries for that name+type. Multiple RRs for the
	//same name+type may be returned in a single query, and will then be retained.
	foreach (cacheme, mapping rr)
	{
		if (rr->cl != Protocols.DNS.C_IN) continue; //Never cache non-IN queries.
		//Replace the TTL with a "time to die" - the timestamp at which the record
		//becomes invalid. Later on, we reverse this process, using the new value
		//of time(), and thus correctly reduce the TTLs. Since the TTL is rounded
		//to an integer, we subtract 1 here, ensuring no hysteresis or other issue.
		rr->ttl += time() - 1;
		cache[cachekey(rr->name, rr->type)] += ({rr});
	}
	//Having gathered all records of the same type, we can now replace them into the
	//global mapping directly. Note that if all the resource records of a given type
	//are removed (eg you remove a CNAME and replace it with an A/AAAA), we will keep
	//the cached version until its TTL expires.
	G->G->dns_cache += cache;
}

//Check the cache for records matching the name/type.
//Flushes out any that are past TTL. Returns 0 rather than an empty array.
array check_cache(string name, int type)
{
	string k = cachekey(name, type);
	array cache = G->G->dns_cache[k];
	if (!cache) return 0;
	int ts = time();
	array response = ({ });
	foreach (cache, mapping rr)
		if (rr->ttl > ts) response += ({ rr + (["ttl": rr->ttl - ts]) });
	if (!sizeof(response))
	{
		//All records have expired. This is more common than partial
		//expiry, especially since a lot of cache entries will be for
		//a single response RR. With partial expiry, we'll keep the
		//entire collection in memory, but return only the ones that
		//are still valid.
		m_delete(G->G->dns_cache, k);
		return 0;
	}
	return response;
}

mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	string name=lower_case(q->name);
	log->write("[%s] [%s] %s %s %s\n", ctime(time())[..<1], ip_to_host(udp_data->ip), name,
		dns_types[q->type] || (string)q->type,
		([Protocols.DNS.C_IN:"IN"])[q->cl] || (string)q->cl,
	);
	mapping resp = sharehosts->dns(portref, query, udp_data, cb);
	if (!resp->rcode) return resp; //It claims to be successful? Fine, return that then.

	//Check the cache for valid records.
	//1) Look for a CNAME for this name. If so, return it.
	//2) Look for a corresponding record of the same type.
	array cnames = ({ });
	if (q->cl == Protocols.DNS.C_IN) //In the unlikely event that we get non-IN queries, just bypass the cache.
	{
		while (array cname = check_cache(name, Protocols.DNS.T_CNAME))
		{
			cnames += cname;
			name = cname[0]->cname; //There should be exactly one record.
		}
		array cache = check_cache(name, q->type);
		if (cache)
		{
			//TODO: Possibly also return other useful records in the ADDITIONAL section
			return (["an": cnames + cache]);
		}
	}
	upstream->do_query(name, q->cl, q->type, respond, cb, cnames);
}

//TODO: Should this instead drop to SUDO_UID/SUDO_GID?
//And should privilege dropping be handled by Hogan, rather than the Goldi?
void drop_perms()
{
	setgid(1000);
	setuid(1000);
	write("Permissions dropped - now u%d/%d g%d/%d\n",getuid(),geteuid(),getgid(),getegid());
}

protected void create()
{
	if (!G->G->dns_cache) G->G->dns_cache = ([]);
	if (!getuid()) call_out(drop_perms,0);
	//Create a reverse mapping from DNS record type to symbolic name
	foreach (indices(Protocols.DNS), string k)
		if (has_prefix(k, "T_")) dns_types[Protocols.DNS[k]] = k[2..];
}
