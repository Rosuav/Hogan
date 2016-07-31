mapping(int:function) services=([53|HOGAN_DNS:dns]);

Protocols.DNS.async_dual_client upstream = Protocols.DNS.async_dual_client();
Stdio.File log = Stdio.File("dnsrequests.log", "wac");

//Convert an IP address to a name from /etc/hosts - somewhat like a reverse DNS
//lookup, but won't go out over the internet. Also, unusually, returns the *last*
//name, not the first, because of how I have my hosts file set up.
string ip_to_host(string ip)
{
	//Lifted from sharehosts.pike
	foreach (Stdio.read_file("/etc/hosts")/"\n",string line)
	{
		sscanf(line,"%s#",line); line=String.normalize_space(line);
		array parts=lower_case(line)/" ";
		if (sizeof(parts)<2) continue; //Ignore this line - probably blank
		if (parts[0] == ip) return ip + "/" + parts[-1];
	}
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
	upstream->do_query(q->name, q->cl, q->type, respond, cb);
}

void drop_perms()
{
	setgid(1000);
	setuid(1000);
	write("Permissions dropped - now u%d/%d g%d/%d\n",getuid(),geteuid(),getgid(),getegid());
}

void create() {if (!getuid()) call_out(drop_perms,0);}
