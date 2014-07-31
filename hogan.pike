#!/usr/bin/env pike

mapping(string:mixed) G=([]); //Generic globally accessible data. Accessible everywhere as G->G->whatever.

string goldiname; //File name of goldilocks - set on startup, not normally changed
object goldi=class{ }(); //Current goldilocks. Will be updated at any time (eg in response to SIGHUP).

mapping(int:object) socket=([]);

constant HOGAN_LINEBASED=0x10000,HOGAN_CONNTYPE=0xF0000; //Connection types (not bitwise, but portref&HOGAN_CONNTYPE will be equal to some value)
constant HOGAN_SSL=0x100000; //Additional flags which can be applied on top of a connection type
string describe_conntype(int portref)
{
	return ([HOGAN_LINEBASED:"LINE"])[portref&HOGAN_CONNTYPE]||"";
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

void _write(mapping(string:mixed) conn,string data) {if (data) conn->_writeme+=data; socket_write(conn);}

void socket_callback(mapping(string:mixed) conn,string data)
{
	string writeme;
	if (mixed ex=catch {writeme=goldi->services[conn->_portref](conn,data);})
	{
		werror("Error in port %s handler:\n%s\n",describe_portref(conn->_portref),describe_backtrace(ex));
		return;
	}
	_write(conn,writeme);
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

void accept(int portref)
{
	while (object sock=socket[portref]->accept())
	{
		mapping(string:mixed) conn=(["_sock":sock,"_portref":portref,"_writeme":"","_data":""]);
		sock->set_id(conn);
		sock->set_nonblocking(socket_read,socket_write,socket_close);
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
