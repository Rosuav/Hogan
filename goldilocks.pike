#charset utf-8
/*
Template/example Goldilocks script, and self-documentation for same.

Note that if hogan.pike is put into $PATH (or its absolute path is known), this
and any other Goldilocks can be made executable with a shebang. However, this
trick will work only on systems that allow shebangs to shebangs, which is not a
POSIX requirement. (Seems to work on Linux, no idea about other platforms.)

Named after the call-sign used on Hogan's Heroes.
*/

/* A note on strings.

Throughout this code, strings of various types can be found. These generally fall into
one of these categories:

* Untyped "string" - could be anything. Should be avoided.
* string(32bit) - can store any values. Has no semantic meaning. Also generally avoided.
* string(21bit) - Unicode text. This is the most normal human-readable text string.
* string(8bit) - bytes. Arbitrary eight-bit data that can be sent across the internet.
* string(7bit) - ASCII-only text or equivalent bytes. Can be treated as either text (a
		subset of string(21bit)) or as bytes (a subset of string(8bit)), on the
		assumption that conversions between text and bytes will always be done
		using an ASCII-compatible encoding such as UTF-8.

Note that for compatibility with older Pikes, this file uses the older notation:
string(0..127), string(0..255), string(0..1114111), string(0..4294967295)
*/

mapping(int:function) services=([
	//Each service is identified by a port and a type, which is one or more bitflags.
	//This combination is called a "portref" and must be unique. (Note that the same
	//port number can be used twice, although this is not useful unless one of them
	//is UDP and the other TCP.) A portref is mapped to a function (or program/class)
	//which handles its connections.

	//The simplest form simply notifies you on connections and new data. No buffering
	//of input, though output is buffered to prevent blocking. There is no significant
	//difference between being called twice and being called once with the combined
	//strings, and the two should be treated the same.
	7007:echoer,

	//Line-based input buffering will be much more useful, though. This also sets the
	//send suffix to "\n", though this can be overridden.
	2525|HOGAN_LINEBASED:smtp,

	//Telnet command processing can be layered on top of some forms of socket.
	2323|HOGAN_LINEBASED|HOGAN_TELNET:telnet,

	//Socket connections can be encrypted using SSL/TLS, transparently to the code.
	//It's perfectly conceivable to use the same callback for the non-SSL and SSL
	//ports offering the same service (eg 143 and 993|HOGAN_SSL), easily checking
	//conn->_portref&HOGAN_SSL to distinguish when necessary (eg to deny plaintext
	//authentication when the connection's not encrypted), otherwise sharing code.
	//UTF-8 encoding and decoding can be layered on top of sockets, too. Note that
	//the layers are in sequence; SSL, then Telnet, then UTF-8, then splitting into
	//lines, as many of them as are applicable.
	1234|HOGAN_LINEBASED|HOGAN_UTF8:text,

	//UDP packets can be received on any given port. This does not conflict with a
	//TCP socket on the same port number (for obvious reasons). UDP sockets cannot
	//use most of the above flags, although UTF-8 decoding is supported.
	5300|HOGAN_UDP:dnsdump,

	//Full DNS protocolling can be handled properly, which is a lot easier than the
	//basic UDP interface. If the lower-level support is available, this will be a
	//dual UDP/TCP server; otherwise, it'll be pure UDP, with the limitations that
	//that entails.
	5301|HOGAN_DNS:dns,

	//With active connections, Hogan won't establish them automatically. Establish
	//one manually by calling G->connect() with a conn mapping. Note that low ports
	//do not require privileges for active connections.
	25|HOGAN_ACTIVE|HOGAN_LINEBASED:smtp,

	//More flags will be added later, eg HTTP.
	//Incompatible flag combinations will be reported to stderr and their portrefs
	//ignored. On startup, this will prevent backend loop initiation.
]);

//Simple TCP socket server. Each connection is associated with mapping(string:mixed), and
//this function is called for new connections, data arrival, and disconnection.
//Hogan provides and uses certain information in the mapping, all with keys beginning with
//underscores. They may be read freely, but undocumented mutation may cause problems - use
//at your own risk.
//conn->_sock: Stdio.File for the connected socket (don't read/write directly)
//conn->_portref: Port reference as used in services[]
//conn->_writeme: Buffered data for writing (may be a string(0..255) or a Stdio.Buffer); is
//  always bytes, not Unicode text
//conn->_written: Number of bytes of _writeme already written. Used only if _writeme is
//  more than WRITE_CHUNK long (and ergo only if WRITE_CHUNK is set) and if Stdio.Buffer is
//  not available.
//conn->_closing: Flag set to 1 when connection is closed; see usage example.
//conn->_close: Set this to 1 to request that the connection be closed once all buffered
//  data is written (including anything returned from this call)
//conn->_sendsuffix: String appended to every string sent. Defaults to "" unless LINEBASED.
//Keys in conn[] which do NOT begin with an underscore are entirely yours. Hogan will never
//read or change them.
//Any returned string will be sent to the client. You can also send to a conn explicitly:
//    G->send(conn,"Hello, world!");
string(0..255) echoer(mapping(string:mixed) conn,string(0..255) data)
{
	if (!data) if (!conn->_closing)
	{
		write("[%08x] New connection\n",hash_value(conn));
		return "Hello!\n";
	}
	else
	{
		write("[%08x] Connection closed\n",hash_value(conn));
		return 0; //Return value ignored
	}
	write("[%08x] %d bytes received\n",hash_value(conn),sizeof(data));
	if (data=="\4") conn->_close=1; //Ctrl-D quits
	else return data;
}

//Line-based TCP socket. Similar to the above, but instead of getting arbitrary data, the
//function receives one line (delimited by \n; any trailing \r will be stripped). By
//default, sent strings have \n appended, though this can be changed (eg to \r\n) by
//setting conn->_sendsuffix.
string(0..255) smtp(mapping(string:mixed) conn,string(0..255) line)
{
	conn->_close=1;
	return "ERROR! Unimplemented!";
}

//Telnet handling changes the function signature. Whenever a complete Telnet sequence is
//read, it will be passed in as an array, eg IAC WILL NAWS comes through as ({WILL,NAWS}).
//Subnegotiation also elides the IAC SE, starting with just the SB and the content.
//IAC doubling is handled automatically, in both directions. To send a Telnet sequence,
//return an array equivalent to what would be received (including elisions).
array(int)|string(0..255) telnet(mapping(string:mixed) conn,string(0..255)|array(int) line)
{
	if (!line)
	{
		if (!conn->_closing) {G->send(conn,({DO,TERMTYPE})); G->send(conn,({DO,NAWS})); return "Hello, and welcome!";}
		return 0;
	}
	if (arrayp(line))
	{
		if ((string)line==(string)({WILL,TERMTYPE})) G->send(conn,({SB,TERMTYPE,SEND}));
		//Attempt to translate Telnet codes back into symbols
		//Not perfect, as meanings are contextual; for instance, inside a NAWS
		//subnegotiation, the values are just numbers, so translating back to
		//mnemonics is less than helpful. It's still true, just not helpful :)
		//Special cases:
		if (has_prefix((string)line,(string)({SB,TERMTYPE,IS}))) return sprintf("Telnet: IAC SB TERMTYPE IS %O",(string)line[3..]);
		if (has_prefix((string)line,(string)({SB,NAWS}))) return sprintf("Telnet: IAC SB NAWS %dx%d",line[2]<<8|line[3],line[4]<<8|line[5]);
		//Default case: Translate everything that can be translated
		program hogan=object_program(G);
		mapping(int:string) consts=([]);
		foreach (indices(hogan),string c) if (intp(hogan[c])) consts[hogan[c]]=c;
		array(string) result=allocate(sizeof(line));
		foreach (line;int i;int val) result[i]=consts[val] || sprintf("0x%02X",val);
		return "Telnet: IAC "+result*" ";
	}
	#if constant(Stdio.IPTOS_LOWDELAY)
	if (int toscode=sscanf(line,"tos %s",string tos) && Stdio["IPTOS_"+upper_case(tos)])
	{
		conn->_sock->setsockopt(Stdio.IPPROTO_IP,Stdio.IP_TOS,toscode);
		return "Type of service set to "+tos;
	}
	#endif
	if (line=="quit") {conn->_close=1; return "Bye!\n";}
	return "Unrecognized command.";
}

//Identical in structure to smtp, but its string arguments are Unicode, not bytes, strings.
string(0..1114111) text(mapping(string:mixed) conn, string(0..1114111) line)
{
	if (!line) {write("Connection: %d/%O\n",conn->_closing,conn->_sock); return 0;}
	write("%O\n",line);
	if (line[-1]=='K') line=(string)(float)line+"°K"; //Cheat for code simplicity: "273.15 K" -> "273.15°K"
	if (sscanf(line,"%f°%c",float deg,int type))
	{
		string desc = type=='K' ? sprintf("%.2f K",deg) : sprintf("%.2f °%c",deg,type);
		//First, convert to Kelvin for consistency.
		switch (type)
		{
			case 'K': break;
			case 'C': deg+=273.15; break;
			case 'F': deg+=459.67; //Which makes it Rankine, so fall through
			case 'R': deg*=5.0/9; break;
			default: return "Unrecognized temperature scale.";
		}
		//Emit conversions to everything other than was originally entered
		if (type!='K') G->send(conn,sprintf("%s = %.2f K",desc,deg));
		if (type!='C') G->send(conn,sprintf("%s = %.2f °C",desc,deg-273.15));
		if (type!='F') G->send(conn,sprintf("%s = %.2f °F",desc,deg*9/5-459.67));
		if (type!='R') G->send(conn,sprintf("%s = %.2f °R",desc,deg*9/5));
		return 0;
	}
	if (line=="quit") {conn->_close=1; return "Bye!";}
	return "Whatever you say.";
}

//UDP sockets have no concept of responses, so the return value is void.
//The data mapping is exactly as provided by Stdio.UDP(), and has the data and
//source ip/port for the packet.
void dnsdump(int portref,mapping(string:int|string) data)
{
	write("DNS packet from %s : %d\n%O\n",data->ip,data->port,data->data);
}

//Apart from portref, the args are exactly as per Protocols.DNS.server()->reply_query(),
//as is the return value and callback handling. Check the docs directly. The parsed
//query is best documented by Protocols.DNS.protocol()->decode_entries() and by the DNS
//RFCs, which you'll probably need to read up on anyway.
mapping dns(int portref,mapping query,mapping udp_data,function(mapping:void) cb)
{
	mapping q=query->qd[0];
	//RFC 1034 stipulates that the domain MUST be lowercased before comparing.
	//However, some DNS resolvers add entropy by randomizing case, and expect the response
	//to be in the original query's case. So if you get a query for "gOLdiLocKS.exaMPlE",
	//it must be responded to as if it were "goldilocks.example", but ideally, it should
	//have the response quote back "gOLdiLocKS.exaMPlE".
	string name=lower_case(q->name);
	write("DNS request: %s %s %s\n",name,
		#define T(x) Protocols.DNS.T_##x:#x
		([T(A), T(AAAA), T(MX), T(NS), T(PTR), T(SOA), T(TXT), T(SPF)])[q->type] || (string)q->type,
		([Protocols.DNS.C_IN:"IN"])[q->cl] || (string)q->cl,
	);
	if (q->cl==Protocols.DNS.C_IN && q->type==Protocols.DNS.T_A && name=="goldilocks.example")
		return (["an":(["cl":q->cl,"ttl":60,"type":q->type,"name":q->name,"a":"127.0.0.1"])]);
	if (q->cl==Protocols.DNS.C_IN && q->type==Protocols.DNS.T_TXT && name=="goldilocks.example")
		//Note that TXT records don't have to be "text" in any meaningful sense - they're actually binary.
		return (["an":(["cl":q->cl,"ttl":60,"type":q->type,"name":q->name,"txt":random_string(32)])]);
	return (["rcode":Protocols.DNS.REFUSED]); //There are many possible ways to reject DNS queries, this is just one of them.
}

void create()
{
	//Called on startup and on any sighup. Any necessary initialization can be done here.
	//Can be omitted if not needed.
}
