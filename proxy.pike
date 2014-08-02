//Passworded proxy server for basic socket connections

mapping(int:function) services=([
	465:proxy,
	23|HOGAN_ACTIVE:proxy,
]);

string(0..255) proxy(mapping(string:mixed) conn,string(0..255) data)
{
	if (!data)
	{
		if (conn->_closing && conn->otherconn && conn->otherconn->_sock && !conn->otherconn->_closing) {conn->otherconn->_close=1; G->send(conn->otherconn,"\r\n--> Connection closed <--\n");}
		if (!conn->_closing && conn->otherconn) {G->send(conn->otherconn,"Connected.\r\n"); return conn->otherconn->buffer;}
		conn->buffer="";
		return "Enter password: ";
	}
	if (conn->otherconn) {G->send(conn->otherconn,data); return 0;} //Normal proxying
	//Initialization
	if (!has_value(conn->buffer+=data,"\n")) return 0;
	sscanf(conn->buffer,"%s\n%s",string line,conn->buffer);
	line-="\r";
	if (line=="quit") {conn->_close=1; return "Bye!\r\n";}
	if (lower_case(line)-" "!="rosuavisageek") return "Nope!\r\nEnter password: ";
	write("Correct password from %s\n",conn->_sock->query_address());
	G->connect(conn->otherconn=(["_portref":23|HOGAN_ACTIVE,"_ip":"64.253.105.42","otherconn":conn]));
	return "Connecting, please wait...\r\n";
}
