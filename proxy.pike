//Passworded proxy server for basic socket connections

mapping(int:function) services=([
	465|HOGAN_TELNET:proxy,
	23|HOGAN_ACTIVE|HOGAN_TELNET:proxy,
]);

//Specify a password on the command line, or use the default. Either way, it's not highly
//secure - it's just to stop accidental usage.
string password = G->options->password || "rosuavisageek";

array(int)|string(0..255) proxy(mapping(string:mixed) conn,string(0..255)|array(int) data)
{
	if (!data)
	{
		if (conn->_closing && conn->otherconn && conn->otherconn->_sock && !conn->otherconn->_closing) {conn->otherconn->_close=1; G->send(conn->otherconn,"\r\n--> Connection closed <--\n");}
		if (!conn->_closing && conn->otherconn)
		{
			//Connection established.
			G->send(conn->otherconn,"Connected.\r\n");
			G->send(conn,conn->otherconn->telnets[*]);
			return conn->otherconn->buffer;
		}
		conn->buffer=""; conn->telnets=({ });
		return "Enter password: ";
	}
	if (conn->otherconn) {G->send(conn->otherconn,data); return 0;} //Normal proxying
	//Initialization
	if (arrayp(data)) {conn->telnets+=({data}); return 0;}
	if (!has_value(conn->buffer+=data,"\n")) return 0;
	sscanf(conn->buffer,"%s\n%s",string line,conn->buffer);
	line-="\r";
	if (line=="quit") {conn->_close=1; return "Bye!\r\n";}
	if (lower_case(line)-" "!=password) return "Nope!\r\nEnter password: ";
	write("Correct password from %s\n",conn->_sock->query_address());
	G->connect(conn->otherconn=(["_portref":23|HOGAN_ACTIVE|HOGAN_TELNET,"_ip":"64.253.105.42","otherconn":conn]));
	return "Connecting, please wait...\r\n";
}
