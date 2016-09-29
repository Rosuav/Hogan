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

void respond(string name, mapping info, function(mapping:void) cb) {cb(info);}

mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	string name=lower_case(q->name);
	log->write("[%s] [%s] %s %s %s\n", ctime(time())[..<1], ip_to_host(udp_data->ip), name,
		#define T(x) Protocols.DNS.T_##x:#x
		([T(A), T(AAAA), T(MX), T(NS), T(PTR), T(SOA), T(TXT), T(SPF)])[q->type] || (string)q->type,
		([Protocols.DNS.C_IN:"IN"])[q->cl] || (string)q->cl,
	);
	mapping resp = sharehosts->dns(portref, query, udp_data, cb);
	if (!resp->rcode) return resp; //It claims to be successful? Fine, return that then.
	//TODO: Cache upstream's queries (based on TTLs)
	//Cache can be stored in G->G so it's retained across SIGHUP, but needn't be
	//retained on disk or anything.
	upstream->do_query(q->name, q->cl, q->type, respond, cb);
}

//TODO: Should this instead drop to SUDO_UID/SUDO_GID?
//And should privilege dropping be handled by Hogan, rather than the Goldi?
void drop_perms()
{
	setgid(1000);
	setuid(1000);
	write("Permissions dropped - now u%d/%d g%d/%d\n",getuid(),geteuid(),getgid(),getegid());
}

void create() {if (!getuid()) call_out(drop_perms,0);}
