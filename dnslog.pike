mapping(int:function) services=([53|HOGAN_DNS:dns]);

mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	string name=lower_case(q->name);
	write("DNS request: %s %s %s\n",name,
		#define T(x) Protocols.DNS.T_##x:#x
		([T(A), T(AAAA), T(MX), T(NS), T(PTR), T(SOA), T(TXT), T(SPF)])[q->type] || (string)q->type,
		([Protocols.DNS.C_IN:"IN"])[q->cl] || (string)q->cl,
	);
}

void drop_perms()
{
	setgid(1000);
	setuid(1000);
	write("Permissions dropped - now u%d/%d g%d/%d\n",getuid(),geteuid(),getgid(),getegid());
}

void create() {call_out(drop_perms,0);}
