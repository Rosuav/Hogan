#!/usr/bin/env pike

mapping(string:mixed) G=([]); //Generic globally accessible data. Accessible everywhere as G->G->whatever.
mapping(string:string|int(1..1)) options=([]); //Parsed options from argv[]: "--foo=bar" becomes options->foo="bar", and "--foo" becomes options->foo=1

string goldiname; //File name of goldilocks - set on startup, not normally changed
object goldi=class{ }(); //Current goldilocks. Will be updated at any time (eg in response to SIGHUP).

mapping(int:object) socket=([]);

constant HOGAN_PLAIN=0x00000,HOGAN_LINEBASED=0x10000,HOGAN_UDP=0x20000,HOGAN_DNS=0x30000,HOGAN_CONNTYPE=0xF0000; //Connection types (not bitwise, but portref&HOGAN_CONNTYPE will be equal to some value)
constant HOGAN_TELNET=0x100000,HOGAN_UTF8=0x200000,HOGAN_SSL=0x400000,HOGAN_ACTIVE=0x800000; //Additional flags which can be applied on top of a connection type
string describe_conntype(int portref)
{
	return ({
		([HOGAN_PLAIN:"PLAIN",HOGAN_LINEBASED:"LINE",HOGAN_UDP:"UDP",HOGAN_DNS:"DNS"])[portref&HOGAN_CONNTYPE]||sprintf("0x%X",portref&HOGAN_CONNTYPE),
		(portref&HOGAN_TELNET) && "TELNET",
		(portref&HOGAN_UTF8) && "UTF8",
		(portref&HOGAN_SSL) && "SSL",
		(portref&HOGAN_ACTIVE) && "ACTIVE",
	})*",";
}
string describe_portref(int portref) {return sprintf("%d [%s]",portref&65535,describe_conntype(portref));}

//If conn->_writeme exceeds this many bytes, conn->_written will be used.
//Also, any time conn->_written exceeds this much, it'll be trimmed from _writeme.
//Not set by default as it can impact performance on the common case; the best
//way to use this is: pike -DWRITE_CHUNK=1024*1024*16 hogan somefile.pike
//Probably not needed unless you're writing megs and megs of stuff all at once
//(hence the 16MB example here); you'll know you need this if you see the Hogan
//process become CPU-bound doing the O(N**2) processing needed to send data around.
//#define WRITE_CHUNK 1024*1024*16

void socket_write(mapping(string:mixed) conn)
{
	if (!conn->_sock) return;
	if (conn->_writeme!="" && !conn->_closing && conn->_sock && conn->_sock->is_open())
	{
		#ifdef WRITE_CHUNK
		conn->_written+=conn->_sock->write(conn->_writeme[conn->_written..conn->_written+WRITE_CHUNK]);
		//Trim from _writeme when it becomes completely empty, or when we've written a full chunk.
		if (conn->_written==sizeof(conn->_writeme)) {conn->_written=0; conn->_writeme="";}
		else if (conn->_written>=WRITE_CHUNK) {conn->_writeme=conn->_writeme[conn->_written..]; conn->_written=0;}
		#else
		conn->_writeme=conn->_writeme[conn->_sock->write(conn->_writeme)..];
		#endif
	}
	if (conn->_writeme=="" && conn->_close && !conn->_closing)
	{
		conn->_sock->close();
		socket_close(conn);
	}
}

void writeme(mapping(string:mixed) conn,string data)
{
	if (conn->_sendsuffix) data+=conn->_sendsuffix;
	if (conn->_portref&HOGAN_UTF8) data=string_to_utf8(data);
	conn->_writeme+=data;
}

void send(mapping(string:mixed) conn,string|array(int) data)
{
	if (data)
	{
		if (conn->_portref&HOGAN_TELNET)
		{
			if (arrayp(data))
			{
				data=replace((string)data,"\xFF","\xFF\xFF"); //Double any IACs embedded in a Telnet sequence
				if (data[0]==SB) data+=(string)({IAC,SE});
				conn->_writeme+="\xFF"+data;
			}
			else writeme(conn,replace(data,"\xFF","\xFF\xFF")); //Double any IACs in normal text
		}
		else writeme(conn,data);
	}
	socket_write(conn);
}

void socket_callback(mapping(string:mixed) conn,string|array(int) data)
{
	string writeme;
	if (conn->_portref&HOGAN_UTF8) catch {data=utf8_to_string(data);}; //Attempt a UTF-8 decode; if it fails, fall back on Latin-1.
	if (mixed ex=catch {writeme=goldi->services[conn->_portref](conn,data);})
	{
		werror("Error in port %s handler:\n%s\n",describe_portref(conn->_portref),describe_backtrace(ex));
		return;
	}
	send(conn,writeme);
}

void socket_close(mapping(string:mixed) conn)
{
	conn->_closing=1; socket_callback(conn,0); //Signal connection close with null data and _closing set
	conn->_sock=0; //Break refloop
}

void socket_read(mapping(string:mixed) conn,string data)
{
	int type=conn->_portref&HOGAN_CONNTYPE;
	if (type==HOGAN_LINEBASED)
	{
		conn->_data+=data-"\r"; //Note that I'm shortcutting \r processing by just dropping them all.
		while (conn->_sock && conn->_sock->is_open() && sscanf(conn->_data,"%s\n%s",string line,conn->_data)) socket_callback(conn,line);
		return;
	}
	socket_callback(conn,data);
}

enum {IS=0x00,ECHO=0x01,SEND=0x01,SUPPRESSGA=0x03,TERMTYPE=0x18,NAWS=0x1F,SE=0xF0,GA=0xF9,SB,WILL,WONT,DO=0xFD,DONT,IAC=0xFF};

void telnet_read(mapping(string:mixed) conn,string data)
{
	conn->_telnetbuf+=data;
	while (sscanf(conn->_telnetbuf,"%s\xff%s",string data,string iac)) if (mixed ex=catch
	{
		socket_read(conn,data); conn->_telnetbuf="\xff"+iac;
		switch (iac[0])
		{
			case IAC: socket_read(conn,"\xFF"); conn->_telnetbuf=conn->_telnetbuf[2..]; break;
			case DO: case DONT: case WILL: case WONT:
			{
				socket_callback(conn,({iac[0],iac[1]}));
				iac=iac[2..];
				break;
			}
			case SB:
			{
				string subneg;
				for (int i=1;i<sizeof(iac);++i)
				{
					if (iac[i]==IAC && iac[++i]==SE) {subneg=iac[..i-2]; iac=iac[i+1..]; break;} //Any other TELNET commands inside subneg will be buggy unless they're IAC IAC doubling
				}
				if (!subneg) return; //We don't have the complete subnegotiation. Wait till we do. (Actually, omitting this line will have the same effect, because the subscripting will throw an exception. So this is optional, and redundant, just like this sentence is redundant.)
				socket_callback(conn,(array)replace(subneg,"\xFF\xFF","\xFF"));
				break;
			}
			case SE: break; //Shouldn't happen.
			case GA:
			{
				socket_callback(conn,({GA}));
				iac=iac[1..];
				break;
			}
			default: break;
		}
		conn->_telnetbuf=iac;
	}) return;
	socket_read(conn,conn->_telnetbuf); conn->_telnetbuf="";
}

void accept(object sock,int portref)
{
	mixed conn=sock->query_id(); if (!mappingp(conn)) sock->set_id(conn=([]));
	conn->_sock=sock; conn->_portref=portref; conn->_writeme=conn->_data=conn->_telnetbuf="";
	sock->set_nonblocking((portref&HOGAN_TELNET)?telnet_read:socket_read,socket_write,socket_close);
	if (portref&HOGAN_LINEBASED) conn->_sendsuffix="\n";
	socket_callback(conn,0); //Signal initialization with null data (and no _closing in conn)
}

void acceptloop(int portref)
{
	while (object sock=socket[portref]->accept()) accept(sock,portref);
}

//Basically a closure, but this is simpler than lambdaing everything.
class callback_caller(int portref) {void `()(mixed data)
{
	if (mixed ex=catch {goldi->services[portref](portref,data);})
		werror("Error in port %s handler:\n%s\n",describe_portref(portref),describe_backtrace(ex));
}}

class dns(int portref)
{
	#if constant(Protocols.DNS.dual_server)
	inherit Protocols.DNS.dual_server;
	#else
	inherit Protocols.DNS.server;
	#endif
	void create() {::create(portref&65535);}
	mapping reply_query(mixed ... args) {return goldi->services[portref](portref,@args);}
	void close() {destruct();}
}

void connected(mapping(string:mixed) conn) {accept(conn->_sock,conn->_portref);}
void connfail(mapping(string:mixed) conn)
{
	//May need some kind of callback instead of (or defaulting to?) this stderr output
	//Maybe call the registered service function with 0 data and no socket??
	object sock=m_delete(conn,"_sock");
	werror("Error connecting to %s:%s - %s [%d]\n",conn->_ip,describe_portref(conn->_portref),strerror(sock->errno()),sock->errno());
	sock->close();
}

//Establish a HOGAN_ACTIVE connection
//As a minimum, conn->_portref must be set, and conn->_ip should be the
//destination IP address.
void connect(mapping(string:mixed) conn)
{
	object sock=conn->_sock=Stdio.File(); sock->set_id(conn);
	sock->open_socket();
	sock->set_nonblocking(0,connected,connfail);
	sock->connect(conn->_ip,conn->_portref&65535);
}

//Returns 1 on error, but that's ignored if it's a sighup.
int bootstrap()
{
	program compiled;
	mixed ex=catch {compiled=compile_file(goldiname);};
	if (ex) {werror("Exception in compile!\n"); werror(ex->describe()+"\n"); return 1;}
	if (!compiled) {werror("Compilation failed for %s\n",goldiname); return 1;}
	goldi=compiled();
	werror("Bootstrapped %s\n",goldiname);
	//Make any sockets that we now need (which will be all of them on first load)
	foreach (indices(goldi->services)-indices(socket),int portref) if (!(portref&HOGAN_ACTIVE))
	{
		int port=portref&65535,type=portref&HOGAN_CONNTYPE;
		object sock;
		switch (type)
		{
			case HOGAN_PLAIN: case HOGAN_LINEBASED:
			{
				function acceptsock=acceptloop;
				if (portref&HOGAN_SSL)
				{
					//TODO: Guard with #if to handle other Pike versions and/or absence of SSL support
					//(If no SSL support at all, this MUST throw an error rather than falling back on non-SSL.)
					#if 0
					//Stub, needs expanding (eg key/cert)
					sock=SSL.Port(SSL.Context()); acceptsock=accept;
					#else
					werror("Unsupported flag combination %s - SSL unavailable\n",describe_conntype(portref));
					return 1;
					#endif
				}
				else sock=Stdio.Port();
				if (!sock->bind(port,acceptsock,"::")) {werror("Error binding to %s: %s [%d]\n",describe_portref(portref),strerror(sock->errno()),sock->errno()); return 1;}
				sock->set_id(portref);
				break;
			}
			case HOGAN_UDP:
				if (portref&(HOGAN_SSL|HOGAN_TELNET)) {werror("Unsupported flag combination %s\n",describe_conntype(portref)); return 1;}
				sock=Stdio.UDP()->bind(port,"::")->set_read_callback(callback_caller(portref));
				break;
			case HOGAN_DNS:
				//Note that while DNS over SSL makes little sense with UDP, it is theoretically
				//possible over TCP. But I've never seen anyone do it; DNSSEC is more effective
				//and much better suited to the protocol.
				if (portref&(HOGAN_SSL|HOGAN_TELNET|HOGAN_UTF8)) {werror("Unsupported flag combination %s\n",describe_conntype(portref)); return 1;}
				sock=dns(portref);
				break;
			default: werror("Unknown connection type %d|%X\n",port,type); return 1;
		}
		socket[portref]=sock;
		write("Bound to %s.\n",describe_portref(portref));
	}
	//Dispose of any sockets we no longer need (none, on first load)
	m_delete(socket,(indices(socket)-indices(goldi->services))[*])->close();
}

int main(int argc,array(string) argv)
{
	add_constant("G",this);
	foreach (argv[1..],string arg)
	{
		if (arg=="") ;
		else if (sscanf(arg,"--%s=%s",string opt,string val)) options[opt]=val;
		else if (sscanf(arg,"--%s",string opt)) options[opt]=1;
		else if (!goldiname) goldiname=arg;
	}
	if (!goldiname) exit(1,"USAGE: pike %s some_file.pike\nSee goldilocks.pike for an example file to invoke.\n",argv[0]);
	if (!file_stat(goldiname) && file_stat(goldiname+".pike")) goldiname+=".pike";
	if (options->install)
	{
		//Attempt to install this goldi as a systemd service.
		//Note that, if this works, non-restart reloading can be done with:
		//  sudo systemctl kill -s HUP goldilocks.service
		string pike=master()->_pike_file_name; //Reaching into private space? Hmm.
		if (!has_prefix(pike,"/")) pike=Process.search_path(pike);
		string svc=(goldiname/".")[0]+".service";
		Stdio.File("/etc/systemd/system/"+svc,"wct")->write(#"[Unit]
Description=Hogan calling on %s

[Service]
Environment=DISPLAY=%s
WorkingDirectory=%s
ExecStart=%s %s %[0]s
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
",goldiname,getenv("DISPLAY")||"",getcwd(),pike,argv[0]);
		Process.create_process(({"systemctl","--system","daemon-reload"}))->wait();
		Process.create_process(({"systemctl","enable",svc}))->wait();
		Process.create_process(({"systemctl","start",svc}))->wait();
		exit(0,"Installed as %s and started.\n",svc);
	}
	program me=this_program; //Note that this_program[const] doesn't work in old Pikes, so assign it to a temporary.
	foreach (indices(me),string key) add_constant(key,me[key]); //Make constants available globally
	if (bootstrap()) return 1; //Return value checked only on startup. On sighup, those errors won't be fatal.
	signal(1,bootstrap); //On non-Unix platforms, this won't work.
	werror("Ready and listening, pid %d - %s",getpid(),ctime(time()));
	return -1;
}
