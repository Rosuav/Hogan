//Demo of a marginally useful DNS server: it looks up your /etc/hosts and returns results from it.
//This isn't terribly useful (if you actually want to make this kind of thing public, you probably
//want BIND9 rather than something this simple), and for simplicity's sake it doesn't return any
//SOA or NS records, but it's a demo of how easy DNS handling can be.
mapping(int:function) services=([53|HOGAN_DNS:dns]);

constant TTL=60; //Tune according to your requirements. The hosts file doesn't have TTLs, obviously.
constant SEARCH_DOMAIN = ".garden.rosuav.com"; //Names in this domain (with leading dot) are accepted as hostname lookups.

//Normalize an IPv4 or IPv6 address
//In theory, any two strings representing the same address will normalize
//to exactly the same string. This may not be entirely achieved as yet though.
string normalize_address(string addr)
{
	if (has_value(addr,':')) return Protocols.IPv6.normalize_addr_short(addr) || addr;
	sscanf(addr,"%d.%d.%d.%d",int a,int b,int c,int d);
	return sprintf("%d.%d.%d.%d",a,b,c,d);
}

mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	string name = lower_case(q->name) - SEARCH_DOMAIN;
	write("DNS request: %s %s %s\n",name,
		#define T(x) Protocols.DNS.T_##x:#x
		([T(A), T(AAAA), T(MX), T(NS), T(PTR), T(SOA), T(TXT), T(SPF)])[q->type] || (string)q->type,
		([Protocols.DNS.C_IN:"IN"])[q->cl] || (string)q->cl,
	);
	if (q->cl==Protocols.DNS.C_IN) switch (q->type)
	{
		case Protocols.DNS.T_PTR:
			//Hack: Convert the address into human format. IPv6 addresses should have one hex digit per
			//dot, and we group them in fours with colons; IPv4 addresses have one section per dot, so
			//we just reverse them around their dots.
			if (has_suffix(name,".ip6.arpa")) name=normalize_address(reverse((name-".ip6.arpa")-".")/4*":");
			else name=normalize_address(reverse((name-".in-addr.arpa")/".")*".");
			write("PTR request for %s\n",name);
		case Protocols.DNS.T_A:
		case Protocols.DNS.T_AAAA:
			foreach (Stdio.read_file("/etc/hosts")/"\n",string line)
			{
				sscanf(line,"%s#",line); line=String.normalize_space(line);
				array parts=lower_case(line)/" ";
				if (sizeof(parts)<2) continue; //Ignore this line - probably blank
				//PTR records match the first field (IP address) and return the second (canonical name).
				if (q->type==Protocols.DNS.T_PTR && normalize_address(parts[0])==name)
					return (["an":(["cl":q->cl,"ttl":TTL,"type":q->type,"name":q->name,"ptr":parts[1]])]);
				//A records match any field after the first (canonical name or alias) and return the first (IP address),
				//but only if there is no colon in the IP address - that is, if it's an IPv4 address.
				if (q->type==Protocols.DNS.T_A && !has_value(parts[0],':') && has_value(parts[1..],name))
					return (["an":(["cl":q->cl,"ttl":TTL,"type":q->type,"name":q->name,"a":parts[0]])]);
				//AAAA records match the same way A records do, but pick up those that *do* have colons (IPv6 addresses).
				if (q->type==Protocols.DNS.T_AAAA && has_value(parts[0],':') && has_value(parts[1..],name))
					return (["an":(["cl":q->cl,"ttl":TTL,"type":q->type,"name":q->name,"aaaa":parts[0]])]);
			}
			return (["rcode":Protocols.DNS.NXDOMAIN]);
	}
	return (["rcode":Protocols.DNS.REFUSED]); //There are many possible ways to reject DNS queries, this is just one of them.
}

void drop_perms()
{
	setgid(1000);
	setuid(1000);
	write("Permissions dropped - now u%d/%d g%d/%d\n",getuid(),geteuid(),getgid(),getegid());
}

void create() {if (!getuid()) call_out(drop_perms,0);}
