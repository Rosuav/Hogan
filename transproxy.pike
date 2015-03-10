//Transparent proxy server for basic socket connections

mapping(int:function) services=([
	465:proxy,
	10180|HOGAN_ACTIVE:proxy,
]);

string(0..255) proxy(mapping(string:mixed) conn,string(0..255) data)
{
	if (!data)
	{
		if (conn->_closing && conn->otherconn && conn->otherconn->_sock && !conn->otherconn->_closing) {conn->otherconn->_close=1;}
		write("Connection from %s\n",conn->_sock->query_address());
		if (!conn->_closing && conn->otherconn) {return "";}
		G->connect(conn->otherconn=(["_portref":10180|HOGAN_ACTIVE,"_ip":"54.252.89.123","otherconn":conn]));
		return "";
	}
	if (conn->otherconn) {G->send(conn->otherconn,data); return 0;} //Normal proxying
	return "Unknown state...\r\n";
}
