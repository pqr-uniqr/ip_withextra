/*
 * =====================================================================================
 *
 *       Filename:  node.c
 *
 *    Description:  The source code for the node executable
 *
 *        Version:  1.0
 *        Created:  10/03/2013 04:40:46 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hyun Sik (Pete) Kim, Mani Askari
 *   Organization:  Brown University
 *
 * =====================================================================================
 */

#include "csupport/parselinks.c"
#include "csupport/list.c"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
<<<<<<< HEAD
#include <stdbool.h>

=======
#include "csupport/colordefs.h"
>>>>>>> 1e3f5efe0e95341eb8cc1e5e2387881b43bc2cdd

#define RECVBUFSIZE 65536
#define CMDBUFSIZE 1024
#define LOCALDELIVERY 1
#define FORWARD 0

<<<<<<< HEAD
typedef struct{
	int id;
	int sockfd;
	struct sockaddr sourceaddr;
	struct sockaddr destaddr;
	uint32_t sourcevip;
	uint32_t destvip;
	bool status;
}interface_t;

typedef struct {
	uint32_t cost;
	uint32_t addr;
	uint32_t nexthop;
	time_t refreshtime;
	bool local;
}rtu_routing_entry;

=======
int interface_count = 0;
list_t *ref;
int parse_lxnFile(char *filename);
>>>>>>> 1e3f5efe0e95341eb8cc1e5e2387881b43bc2cdd


	void
print_interfaces () 
{



}		/* -----  end of function print_interface  ----- */


	void
print_routes () 
{


}		/* -----  end of function print_routes  ----- */



/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_socket
 *  Description:  
 * =====================================================================================
 */
	int
get_socket (char *port, struct addrinfo *source, int type, int local)
{
	struct addrinfo *p;
	int sockfd, yes = 1;

	if(get_addr(port, source, type, local) == -1){
		printf("get_addr()\n");
		exit(1);
	}
 
	for(p = source; p!=NULL; p=p->ai_next){
		if((sockfd= socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			perror("socket()");
			continue;
		}
		if(bind(sockfd, p->ai_addr, p->ai_addrlen) != 0){
			perror("bind()");
			close(sockfd);
			continue;
		}

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt()");
			exit(1);
		}
		break;
	}

	return sockfd;
}		/* -----  end of function get_socket  ----- */



struct interface_t *only_interface;
struct rtu_routing_entry *only_entry;

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  
 * =====================================================================================
 */
	int
main ( int argc, char *argv[] )
{

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}


	
<<<<<<< HEAD
	//<-SETUP->
	if(setup_interface(argv[1]) == -1){
		printf("setup_interface() went wrong\n");
		exit(1);
	}

	only_entry = local_routing_setup(only_interface);

	//<-WARNING->Intentionally did not set up FD for the socket: not necessary at this point
	fd_set readfds;
	fd_set masterfds;
	FD_ZERO(&masterfds);
	FD_ZERO(&readfds);
	FD_SET(0, &masterfds);
	struct timeval tv, tvcopy;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = 2;

	char command[CMDBUFSIZE];
	int command_bytes;
	while(1){
		readfds = masterfds;
		tvcop = tv;
		if(select(maxfd+1, &readfds, NULL, NULL, &tvcop) == -1){
			perror("select()");
			exit(1);
		}

		printf("select() released\n");
		if(FD_ISSET(0)){
			command_bytes = read(0, command, CMDBUFSIZE);

			if(command_bytes == -1){
				perror("read");
				exit(-1);
			}

			command[command_bytes] = '\0';

			if(strcmp("routes", command) || strcmp("r",command)){
				print_routes();
			}
			
			if(strcmp("interfaces", command) || strcmp("i", command)){
				print_interfaces();
			}
		}

	}


	





=======
	parse_lxnFile(argv[1]);
	
>>>>>>> 1e3f5efe0e95341eb8cc1e5e2387881b43bc2cdd
	return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */


/*
 * == setup_interface(char *filename) =================================================
 * 
 * 
 * ====================================================================================
 */ 

int get_addr(char *portnum, struct addrinfo *addr, int type, int local) {
	
	
	int status;
	struct addrinfo hints;
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;
	
	if (local == 1) {
		hints.ai_flags = AI_PASSIVE;
	}
	
	if ((status = getaddrinfo(NULL, portnum, &hints, &addr)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}
	
	return 1;
}


int parse_lxnFile(char *filename) {
	
	printf(_NORMAL_"Link file -> \"%s\"\n", filename);
	ref = parse_links(filename);
	
	node_t *curr;
	int i = 1;
	
	for (curr = ref->head; curr != NULL; curr = curr->next) {
		
		
        link_t *sing = (link_t *)curr->data;
        
        printf(_BLUE_"\t%s\t%d\t\t%s\t\n"_BLUE_, sing->local_phys_host,sing->local_phys_port, inet_ntoa(sing->local_virt_ip));
		printf(_BLUE_"\t%s\t%d\t\t%s\t\n"_BLUE_, sing->remote_phys_host,sing->remote_phys_port, inet_ntoa(sing->remote_virt_ip));
		
	}
	
}


























