//Test routing and see if it's what you expect
#if constant(G)
mapping(int:function) services=([
	4321|HOGAN_LINEBASED:routing,
]);

string routing(mapping(string:mixed) conn,string line)
{
	if (!line) return 0;
	if (line=="quit") {conn->_close=1; return 0;}
	sscanf(line,"%s %s",string dest,string expected);
	if (!dest || !expected) return 0;
	sscanf(Process.run(({"ip","route","get",dest}))->stdout,"%s\n",string output);
	if (!output) return 0;
	int negate=expected[0]=='!'; //Pass "!via 192.168.0.1" to expect that it NOT contain that
	if (has_value(output,expected[negate..])==negate) {werror(output+"\n"); return output+"\n";}
}
#endif

int main()
{
	while (1)
	{
		string output=String.expand_tabs(Process.run(({"netstat","-nt"}))->stdout);
		Stdio.File sock=Stdio.File(); sock->connect("192.168.0.19",4321);
		int addrpos=-1;
		foreach (output/"\n",string line)
		{
			int pos=search(line,"Foreign Address");
			if (pos!=-1) addrpos=pos;
			else if (addrpos!=-1)
			{
				sscanf(line[addrpos..],"%s:",string ip);
				if (ip && String.trim_all_whites(ip)!="") sock->write(ip+" !via 192.168.0.10\n");
			}
		}
		sock->write("quit\n");
		write(sock->read());
		sleep(60);
	}
}
