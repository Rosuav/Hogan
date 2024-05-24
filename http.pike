mapping(int:function) services=([
	80: dump,
]);

string(0..255) dump(mapping(string:mixed) conn, string(0..255) data) {
	if (conn->_closing) return "";
	conn->_close = 1;
	write("Received connection from %O\n", conn->_sock->query_address());
}
