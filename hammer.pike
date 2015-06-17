mapping(int:function) services=([0|HOGAN_UDP:hammertime]);

//Client: IDs that we're awaiting responses for (mapped to [retry_count, data]), server decryption key
mapping(int:array(int|string)) awaiting=([]);
object decrypt;

//Server: Decryption keys, database connection
mapping(string:object) keys=([]);
int timing=0,packets;
object db=Sql.Sql("pgsql://hammer:hammer@localhost/hammer");

//Both: Encryption key (parsed from the private key file), timing info
object encrypt;
System.Timer starttime;

//Sign and send a packet
void send_packet(string data,string|void ip,int|void port)
{
	object udp=values(G->socket)[0];
	if (sizeof(data)>256) exit(1,"Data too long!\n"); //We want the resulting packet to have no more than 512 data bytes. Boom! Assert fail.
	data += encrypt->pkcs_sign(data,Crypto.SHA256); //The signature should always be exactly 256 bytes (2048 bits) long.
	udp->send(ip||"127.0.0.1",port||5000,data);
}

//Receive and verify a packet
void hammertime(int portref,mapping(string:int|string) data)
{
	if (!timing) write("Packet from %s : %d, %d bytes\n",data->ip,data->port,sizeof(data->data));
	if (sizeof(data->data)<256) return; //Undersized packet, can't have a valid signature
	string body=data->data[..<256], sig=data->data[<255..];
	object decoder=decrypt || keys[data->ip]; //client-mode || server-mode
	if (!decoder) return; //Unrecognized source address
	if (!decoder->pkcs_verify(body,Crypto.SHA256,sig)) return; //Verification failed - bad signature
	//If we get here, then the message cryptographically checked out - yay!
	if (sscanf(body,"OK: %d",int id)) //Client received a server response.
	{
		m_delete(awaiting,id);
		if (timing==1) exit(0,"Response in %f seconds.\n",starttime->peek());
		if (!sizeof(awaiting)) {send_packet("## End ##"); exit(0,"All done.\n");} //Fire-and-forget the final notification.
		return;
	}
	if (body=="## Start ##")
	{
		if (timing++) return; //Were already timing? Nest the starts and ends.
		write("Timing run started!\n");
		starttime=System.Timer();
		packets=0;
		return;
	}
	if (body=="## End ##" && timing)
	{
		if (--timing) return; //Still timing? Tick down and let the nesting continue.
		float tm=starttime->peek();
		write("Timing run complete! %d packets in %f seconds, %f p/s\n",packets,tm,packets/tm);
		return;
	}
	if (timing) ++packets;
	else write("Message body: %s\n",body);
	if (sscanf(body,"Inc %d:%*sID %d",int inc,int id))
	{
		db->query("begin");
		db->query("update hammer set count=count+1 where id=%d", inc);
		db->query("commit");
		send_packet("OK: "+id, data->ip, data->port);
	}
}

//Parse and load a private key for encryption purposes
object load_private_key(string fn)
{
	sscanf(Stdio.read_file(fn),"%*s-----BEGIN RSA PRIVATE KEY-----%s-----END RSA PRIVATE KEY-----",string key);
	return Standards.PKCS.RSA.parse_private_key(MIME.decode_base64(key));
}

//Parse and load a public key for verification purposes
object load_public_key(string fn)
{
	string key=MIME.decode_base64((Stdio.read_file(fn)/" ")[1]);
	//I have no idea how this rewrapping works, but it appears to. There's some
	//signature data at the beginning of the MIME-encoded file, but we need some
	//different signature data for parse_public_key().
	return Standards.PKCS.RSA.parse_public_key("0\202\1\n\2\202"+key[20..]+"\2\3\1\0\1");
}

//packet_count > 1: Throughput test - send a bunch of packets, and let the server time it.
//packet_count == 1: Response time test - send one packet, and see how quickly we get back a response.
void send_all(int packet_count)
{
	//The payload would encode all sorts of useful information, but for now, let's
	//just have a fairly fixed bit of nothing.
	int id=array_sscanf(random_string(4),"%4c")[0]; //Auto-incrementing ID... with a random start.
	timing=packet_count;
	if (timing==1) starttime=System.Timer();
	else send_packet("## Start ##");
	for (int i=0;i<packet_count;++i)
	{
		++id;
		awaiting[id]=({0, sprintf("Inc %d: Hello, world! ID %d, Timestamp %d, ctime %s",random(100)+1,id,time(),ctime(time()))});
		send_packet(awaiting[id][1]);
	}
}

void create()
{
	if (G->options->server)
	{
		services=([5000|HOGAN_UDP:hammertime]);
		if (!file_stat("server_key")) Process.create_process(({"ssh-keygen","-q","-N","","-f","server_key"}))->wait();
		if (!file_stat("demo_key")) Process.create_process(({"ssh-keygen","-q","-N","","-f","demo_key"}))->wait();
		encrypt=load_private_key("server_key");
		keys["127.0.0.1"]=load_public_key("demo_key.pub");
		db->query("begin");
		db->query("drop table if exists hammer");
		db->query("create table hammer (id serial primary key, count integer not null default 0)");
		for (int i=0;i<100;++i) db->query("insert into hammer default values");
		db->query("commit");
		return;
	}
	//Else client mode.
	encrypt=load_private_key("demo_key");
	decrypt=load_public_key("server_key.pub");
	if (G->options->throughput) call_out(send_all,0.01,200);
	else call_out(send_all,0.01,1);
}
