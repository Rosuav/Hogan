mapping(int:function) services=([12345:speed]);

string(0..255) speed(mapping(string:mixed) conn,string(0..255) data)
{
	conn->_close=1;
	if (conn->_closing) {write("%X: done\n",hash_value(conn)); return "";}
	write("%X: New connection from %s\n",hash_value(conn),conn->_sock->query_address());
	return "#"*1024*1024*256;
}

int main(int argc,array(string) argv)
{
	if (argc<2) exit(0,"USAGE: pike %s target_ip\n",argv[0]);
	Stdio.File sock=Stdio.File();
	int start=time(),len=0;
	sock->connect(argv[1],indices(services)[0]);
	while (string x=sock->read(1048576,1))
	{
		if (x=="") break;
		len+=sizeof(x);
		write("%d\r",len/1048576);
	}
	float tm=time(start);
	if (tm==0.0) tm=0.0001; //Prevent div by zero
	len/=1024;
	write("%d KB in %f seconds = %f KB/sec\n",len,tm,len/tm);
}

