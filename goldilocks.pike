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
	//of input, though output is buffered to prevent blocking.
	7007:echoer,

	//Line-based input buffering will be much more useful, though.
	2525|HOGAN_LINEBASED:smtp,

	//More flags will be added later, eg HTTP, TELNET, UDP, DNS, SSL, UTF8, ACTIVE.
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
//Any returned string will be sent to the client.
string echoer(mapping(string:mixed) conn,string data)
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
string smtp(mapping(string:mixed) conn,string line)
{
	conn->_close=1;
	return "ERROR! Unimplemented!\n";
}

void create()
{
	//Called on startup and on any sighup. Any necessary initialization can be done here.
}
