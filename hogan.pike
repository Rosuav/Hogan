#!/usr/bin/env pike

mapping(string:mixed) G=([]); //Generic globally accessible data. Accessible everywhere as G->G->whatever.

string goldiname; //File name of goldilocks - set on startup, not normally changed
object goldi=class{ }(); //Current goldilocks. Will be updated at any time (eg in response to SIGHUP).

mapping(int:object) socket=([]);

constant HOGAN_LINEBASED=0x10000,HOGAN_CONNTYPE=0xF0000; //Connection types (not bitwise, but portref&HOGAN_CONNTYPE will be equal to some value)
constant HOGAN_TELNET=0x100000; //Additional flags which can be applied on top of a connection type
string describe_conntype(int portref)
{
	return ({
		([HOGAN_LINEBASED:"LINE"])[portref&HOGAN_CONNTYPE]||"",
		(portref&HOGAN_TELNET) && "TELNET",
	})*",";
}
string describe_portref(int portref) {return sprintf("%d [%s]",portref&65535,describe_conntype(portref));}

void socket_write(mapping(string:mixed) conn)
{
	if (!conn->_sock) return;
	if (conn->_writeme!="" && !conn->_closing && conn->_sock && conn->_sock->is_open())
		conn->_writeme=conn->_writeme[conn->_sock->write(conn->_writeme)..];
	if (conn->_writeme=="" && conn->_close && !conn->_closing)
	{
		conn->_sock->close();
		socket_close(conn);
	}
}

void send(mapping(string:mixed) conn,string|array(int) data)
{
	if (data)
	{
		if (conn->_portref&HOGAN_TELNET)
		{
			if (arrayp(data))
			{
				data=(string)replace(data,"\xFF","\xFF\xFF"); //Double any IACs embedded in a Telnet sequence
				if (data[0]==SB) data+=(string)({IAC,SE});
				conn->_writeme+="\xFF"+data;
			}
			else conn->_writeme+=replace(data,"\xFF","\xFF\xFF"); //Double any IACs in normal text
		}
		else conn->_writeme+=data;
	}
	socket_write(conn);
}

void socket_callback(mapping(string:mixed) conn,string|array(int) data)
{
	string writeme;
	if (mixed ex=catch {writeme=goldi->services[conn->_portref](conn,data);})
	{
		werror("Error in port %s handler:\n%s\n",describe_portref(conn->_portref),describe_backtrace(ex));
		return;
	}
	send(conn,writeme);
}

void socket_close(mapping(string:mixed) conn)
{
	conn->_closing=1;
	socket_callback(conn,0); //Signal connection close with null data and _closing set
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

void accept(int portref)
{
	while (object sock=socket[portref]->accept())
	{
		mapping(string:mixed) conn=(["_sock":sock,"_portref":portref,"_writeme":"","_data":"","_telnetbuf":""]);
		sock->set_id(conn);
		sock->set_nonblocking((portref&HOGAN_TELNET)?telnet_read:socket_read,socket_write,socket_close);
		socket_callback(conn,0); //Signal initialization with null data (and no _closing in conn)
	}
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
	foreach (indices(goldi->services)-indices(socket),int portref)
	{
		int port=portref&65535,type=portref&HOGAN_CONNTYPE;
		object sock=Stdio.Port();
		if (!sock->bind(port,accept,"::")) {werror("Error binding to %s: %s [%d]\n",describe_portref(port),strerror(sock->errno()),sock->errno()); return 1;}
		sock->set_id(portref);
		socket[portref]=sock;
		write("Bound to %s.\n",describe_portref(portref));
	}
	//Dispose of any sockets we no longer need (none, on first load)
	m_delete(socket,(indices(socket)-indices(goldi->services))[*])->close();
}

int main(int argc,array(string) argv)
{
	add_constant("G",this);
	if (argc<2) exit(1,"USAGE: pike %s some_file.pike\nSee goldilocks.pike for an example file to invoke.\n",argv[0]);
	goldiname=argv[1];
	foreach (indices(this_program),string const) add_constant(const,this_program[const]); //Make constants available globally
	if (bootstrap()) return 1; //Return value checked only on startup. On sighup, those errors won't be fatal.
	signal(1,bootstrap); //On non-Unix platforms, this won't work.
	werror("Ready and listening, pid %d - %s",getpid(),ctime(time()));
	return -1;
}
