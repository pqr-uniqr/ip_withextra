/*
 * =====================================================================================
 *
 *       Filename:  pseudo_2node.c
 *
 *    Description:  pseudocode to get two nodes up, communicating according to the protocol
 *
 *        Version:  1.0
 *        Created:  10/04/2013 01:15:32 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


$DEFINITIONS
	Global Variables
		#list_t *interfaces
		list_t *links <-CONCERN->We probably do not need this.
		#int interface_count
		#fd_set masterfds
		#int maxfd
	Structs
		#struct interface_t{
			int id;
			int sockfd;
			struct sockaddr *soruceaddr;
			struct sockaddr *destaddr;
			uint32_t sourcevip;<-WARNING-> vips are stored with ntohl() applied
			uint32_t destvip; 		reverse the order for IP packet
			bool status;	
		}

		#struct route_entry{
			uint32_t cost;
			uint32_t addr;
			bool local;
		}
	Functions
		#int setup_interface(char *filename)
			-initializes interface list
			-for each line in the lnx file, make an interface and add to the list
			-<-WARNING->Looks like using memcpy to copy sockaddr of source and destination
			has worked out. But if sendto() or recvfrom() gives you problem, this is your
			first bet.
		#int get_socket(uint16_t portnum, struct addrinfo **source, int type)
		#int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local)
			-gets the address of both "local" ports and "remote" ports.
			-"remote" addresses are stored inside interface and used for 
			sending packets later
		*prepare_ip_packet(vip,proto,string)
			*look up interface to send to on routing table
		*send_packet()
		#void print_interfaces()
		void print_routes()

$SETUP
	*setup file descriptor sets(readfds and masterfds)
	*setup interfaces
	*set up routing table with own interfaces
	*send out "hello" to own interface

$EVENT LOOP
	*select()
	*read commands FD_ISSET(0, &readfds)
		#"interfaces"
		*"routes"
		*"send vip() proto(hardcoded to IP 0) string"
			-prepare packet: prepare_ip_packet(vip, proto, string)
			-send packet: 
			
	*recvfrom() packets from UDP sockets
		-if it's an RIP packet, update routing table.
			update_routing_table()
		-if we already have the entry for this guy in the routing table, continue
			
		-if we don't have the guy in the routing table, respond with your own routing table
			!including your own interfaces
$EXIT
	free interface_t list
	close sockets
