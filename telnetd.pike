//Demo of how easy process control can be (if you want it done the dumb way)
//Note that this is every bit as insecure as telnetd otherwise would be,
//plus it's dumb and naive to boot. But if you have some other process that
//you want to invoke, or something, this kind of technique will work.
//Actually, this is even less secure than telnetd, or possibly more secure;
//it doesn't send passwords in clear text across the internet... because it
//doesn't require a password at all! You get direct shell access as the
//account that this script is running as. So be smart: Treat this as a code
//example, and NOT as something you would put on the public internet!
mapping(int:function) services=([2300:telnetd]);

void console_text(mapping(string:mixed) conn,string(0..255) data)
{
	G->send(conn,data);
}

string(0..255) telnetd(mapping(string:mixed) conn,string(0..255) data)
{
	if (!data)
	{
		if (conn->_closing) {conn->proc->kill(signum("HUP")); conn->stdin->close(); conn->stdout->close(); return 0;}
		conn->stdin = Stdio.File(); conn->stdout = Stdio.File();
		conn->stdin->set_id(conn); conn->stdout->set_id(conn);
		conn->stdin->openpt("w"); conn->stdout->openpt("r");
		conn->stdout->set_nonblocking(console_text,0,0);
		object output=Stdio.File(conn->stdout->grantpt(),"w");
		conn->proc = Process.create_process(({"bash","-l"}),([
			"stdin":Stdio.File(conn->stdin->grantpt()),"stdout":output,"stderr":output,
			"callback":lambda() {conn->_close=1; G->send(conn,0);},
		]));
		return 0;
	}
	conn->stdin->write(data);
	return 0;
}
