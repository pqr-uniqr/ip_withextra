
ALMOST COMPREHENSIVE LIST OF SPECIFICATIONS FROM THE ASSIGNMENT PDF


$Operations Logic & details
	#A node has an interface per neighbor
	#Enforce MTU of 1400 bytes
	#Use 64K bytes buffer for receiving
	//?Is it okay to use select()? or are threads better?

$Interface to link layer
	#struct with UDP sockfd, IP addr, portno
	#wrapper functions for socket calls (sendto, recvfrom)
	//any other wrapper functions?

$IP Packets
	*Make them: struct ip!
	*pack in network byte order
	*Encapsulate them
	*deencapsulate them
	*Receive in a struct ip
	*unpack in network byte order
	*ignore IP options

*Make the decision: Local Delivery VS Forwarding

$Forwarding
	//?What does a forwarding table look like?
	//?How do I give RIP info to the module?
	//?What constitutes the forwarding table? is it an external file?

$Local Delivery (what exactly is this? packet meant for this computer?
	*Make an abstract interface that lets upper protocols register handlers
		typedef void (*handler_t) (interface_t *, struct ip*)
		void net_register_handler(uint8_t protocol_num, handler_t handler)
	*if RIP -> routing, else -> print

$Command-line commands
	*"interfaces"
	*"routes"
	*"down(int)"
	*"up(int)"
	*"send(vip, proto, string)"



$Learning to use helpful stuff
	*Try manually parsing and running AB.net
	*write a network topology file, pass to net2nlx, runNode
	-loop.net
	*Once you make an IP packet, try using ipsum.c
	//list.c: where would this come in handy? list of socket interfaces?
	//list.c is used for parselinks.c 
	//hashtable.c: where would I use this? Is this the body of the forwarding table?
	
