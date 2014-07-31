/*
Template/example Goldilocks script, and self-documentation for same.

Note that if hogan.pike is put into $PATH (or its absolute path is known), this
and any other Goldilocks can be made executable with a shebang. However, this
trick will work only on systems that allow shebangs to shebangs, which is not a
POSIX requirement. (Seems to work on Linux, no idea about other platforms.)

Named after the call-sign used on Hogan's Heroes.
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

	//Line-based input buffering will be much more useful, though. Note that this is
	//input buffering, and does not affect output at all; most of these flags apply
	//to both input and output.
	2525|HOGAN_LINEBASED:smtp,

	//Telnet command processing can be layered on top of some forms of socket.
	2323|HOGAN_LINEBASED|HOGAN_TELNET:telnet,

	//UTF-8 encoding and decoding can be layered on top of sockets, too. Note that
	//the layers are in strict sequence; Telnet, then UTF-8, then splitting into
	//lines, as many of them as are applicable.
	1234|HOGAN_LINEBASED|HOGAN_UTF8:text,

	//More flags will be added later, eg HTTP, UDP, DNS, SSL, ACTIVE.
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
//conn->_writeme: Buffered data for writing
//conn->_closing: Flag set to 1 when connection is closed; see usage example.
//conn->_close: Set this to 1 to request that the connection be closed once all buffered
//  data is written (including anything returned from this call)
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
//function receives one line (delimited by \n; any trailing \r will be stripped).
string(0..255) smtp(mapping(string:mixed) conn,string(0..255) line)
{
	conn->_close=1;
	return "ERROR! Unimplemented!\n";
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
		if (!conn->_closing) {G->send(conn,({DO,TERMTYPE})); G->send(conn,({DO,NAWS})); return "Hello, and welcome!\n";}
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
		if (has_prefix((string)line,(string)({SB,TERMTYPE,IS}))) return sprintf("Telnet: IAC SB TERMTYPE IS %O\n",(string)line[3..]);
		if (has_prefix((string)line,(string)({SB,NAWS}))) return sprintf("Telnet: IAC SB NAWS %dx%d\n",line[2]<<8|line[3],line[4]<<8|line[5]);
		//Default case: Translate everything that can be translated
		program hogan=object_program(G);
		mapping(int:string) consts=([]);
		foreach (indices(hogan),string c) if (intp(hogan[c])) consts[hogan[c]]=c;
		array(string) result=allocate(sizeof(line));
		foreach (line;int i;int val) result[i]=consts[val] || sprintf("0x%02X",val);
		return "Telnet: IAC "+result*" "+"\n";
	}
	if (line=="quit") {conn->_close=1; return "Bye!\n";}
	return "Unrecognized command.\n";
}

//Identical in structure to smtp, but its string arguments are Unicode, not bytes, strings.
string text(mapping(string:mixed) conn,string line)
{
	if (!line) return 0;
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
			default: return "Unrecognized temperature scale\n";
		}
		//Emit conversions to everything other than was originally entered
		if (type!='K') G->send(conn,sprintf("%s = %.2f K\n",desc,deg));
		if (type!='C') G->send(conn,sprintf("%s = %.2f °C\n",desc,deg-273.15));
		if (type!='F') G->send(conn,sprintf("%s = %.2f °F\n",desc,deg*9/5-459.67));
		if (type!='R') G->send(conn,sprintf("%s = %.2f °R\n",desc,deg*9/5));
		return 0;
	}
	if (line=="quit") {conn->_close=1; return "Bye!\n";}
	return "Whatever you say.\n";
}

void create()
{
	//Called on startup and on any sighup. Any necessary initialization can be done here.
}
