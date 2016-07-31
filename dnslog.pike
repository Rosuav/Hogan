mapping(int:function) services=([53|HOGAN_DNS:dns]);

Protocols.DNS.async_dual_client upstream = Protocols.DNS.async_dual_client();

void respond(string name, mapping info, function(mapping:void) cb) {cb(info);}

mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	string name=lower_case(q->name);
	write("[%s] [%s] %s %s %s\n", ctime(time())[..<1], udp_data->ip, name,
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

void create() {call_out(drop_perms,0);}
