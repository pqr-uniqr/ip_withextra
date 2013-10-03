
----------------------------------------------------------------------------------------------------------------------------
$DEFINITIONS
	*Functions
		ssize_t forward(interface_t *interface, char *data)
			-usage: command send, received packet is to be sent again
			*enforce MTU of 1400 bytes here:

		ssize_t receive_packet(interface_t *interface, char *buf)
			<-CONCERN->?char * or char **
			bytes = recvfrom(interface->udp_sockfd, buffer of size 64k (recvbuf), 64k, 0(options);

		list_t *setup_interface(char *filename)
			<-PSEUDO-> Usage: setup_interface(arg[1])
				struct list_t *link_list_head= parse_links(filename)
				struct node_t *ln
				for(ln=list_of_links->head; ln!=NULL;ln=ln->next)

		int inspect_ip_header(char *packet);
			<-CONCERN-> packet: the whole packet or just the 5-word header
			<-EXTRACREDIT-> check if ident field is empty
	
		void net_register_handler(uint8_t protocol_num, handler_t handler)

	*Structs
		typedef struct
			int udp_sockfd
			int port_no
			int up
			struct ip *dest_addr
		interface_t 

	*Macros
		#define RECVBUFSIZE 65536
		#define LOCALDELIVERY 1
		#define FORWARD 0


----------------------------------------------------------------------------------------------------------------------------
$SETUP
	*declare variables
		list_t *list_of_interfaces
		char *recvbuf = malloc(RECVBUFSIZE);
		interface_t *interface;
		node_t *curr;
		struct ip empty_ip_header;
		
	*set up link layer "interfaces"
		<-MODULE->list_of_interfaces = setup_interface(argv[1]);

	*register handlers for protocol No. 200 (RIP) and protocol NO. 0 (test)
		<-MODULE->net_register_handler(200,(*handler_t)&rip_handler)
		<-QUESTION-> Is this how I'd use it

	*set up for select() call


----------------------------------------------------------------------------------------------------------------------------
$EVENT LOOP
	*select() for async polling on FDs 

	*read() commands
		*trivial cases
		*"interface, routes"
			for interface in list_of_interfaces
				print info
			for entry in routing table
				print info
		*down int, up int
			<-QUESTION->what is the int--what identifies an interface?
			<-QUESTION->How to bring an interface "down" (or "up")

		*send vip, proto, string
			struct ip newaddress
			newaddress.ip = vip newaddress.proto = proto 
			<-MODULE-> forward(newaddress, string) 
			<-CONCERN-> Edge case: what if vip is one of my own interfaces

	*read packets and deal with it
		for curr = list_of_interfaces;curr !=NULL;curr = curr->next
			interface = (interface_t *) curr->data
			if FD_ISSET(interface->udp_sockfd)

				<-MODULE->bytes = receive_packet(interface, recvbuf);

				if(bytes == -1)
					->system broke
					->notify and break() away into safe exit!

				if(bytes == 0)
					->connection terminated -> node down!
					->you probably want to tell the routing module about this
					->continue()
						<-CONCERN->but should I not wait for the forwarding table to be updated?
							that is, before I can continue to the next interface-- this might
							support select() over threads

				<-MODULE->decision = inspect_ip_header(recvbuf, 64k, &emtpy_ip_header)
				
				if(decision == -1)
					->system broke
					->notify and break() away into safe exit!

				if(decision == LOCALDELIVERY)
					->the packet was for one of our interfaces
					-><-QUESTION->how to trigger handler?

				if(decision == FORWARD)
					->the packet is not for one of our interfaces
					-><-EXTRACREDIT-> 
					-><-MODULE->forward(&empty_ip_header)

	*quick chat with the routing module: "Do I need to send out some RIP packets?"
		
						
----------------------------------------------------------------------------------------------------------------------------
$Exit 
	free_links()
	free the buffer used for recvfrom()

