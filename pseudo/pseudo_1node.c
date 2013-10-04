/*
 * =====================================================================================
 *
 *       Filename:  pseudo_1node.c
 *
 *    Description:  pseudocode to get 1 node up and running 
 *
 *        Version:  1.0
 *        Created:  10/03/2013 05:16:28 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

$Definitions
	*global variable
		interface_listhead: global variable that stores the list of interfaces
		interface count: global int that counts intefaces. also give interfaces ids.
		link_t links: 
	*structs
		#struct interface_t{
			int id;
			int sockfd;
			struct sockaddr *sourceaddr;
			struct sockaddr *destaddr;
			uint32_t sourcevip;
			uint32_t destvip;
			bool status;
		}

		#struct rtu_routing_entry{
			uint32_t cost;
			uint32_t addr;
			uint32_t nexthop;
			time_t refreshtime;
			bool local;
		}
		-this struct needs an id, which will be the hash of the vip
		-this struct will be stored inside the hash table
		-list of entry 

		struct routing_table{
			struct *rtu_routing_entry first_route;
			
		}
	*functions
		int setup_interface(char *filename)
			-if returns -1, error parsing
			*make the ids
			*make sockaddrs
			*set up the sockets
			*store the vips

		#int get_socket(char *portnum, struct addrinfo *source, int type)
			*returns sockfd
			*use getaddrinfo on both local and remote ports

		#int get_addr(char * portnum, struct sockaddr *addr, int type, int local)

		rtu_routing_entry *local_routing_setup(struct interface_t *interface)
			-this function takes in an interface struct and gives back
			a routing_entry
			!!! for now, we only have one routing entry per node, so don't 
			worry about the hashtable.

		print_interface()
			

		print_routes()

$Setup
	*Declaration
	*Set up link layer interfaces
		setup_interface(argv[1]);

	*routing table setup procedure
		local_routing_setup();
	
	*set up for select() call
	
$Event Loop
	*select()

	*read() commands
		*trivial cases
		*"interfaces, routes"
			print_interface()
			print_route()


$Exit
	free interface_t list
