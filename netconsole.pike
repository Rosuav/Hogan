//Receiver for netconsole traces

mapping(int:function) services=([
	6666|HOGAN_UDP: trace,
]);

void trace(mapping(string:mixed) conn, mapping pkt) {
	write("%s\n", /*pkt->ip,*/ String.trim(pkt->data));
}
