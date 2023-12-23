//Receiver for netconsole traces

mapping(int:function) services=([
	6666|HOGAN_UDP: trace,
]);

void trace(int portref, mapping(string:int|string) pkt) {
	write("%s\n", /*pkt->ip,*/ String.trim(pkt->data));
}
