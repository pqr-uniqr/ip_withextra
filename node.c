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
#include <stdbool.h>
#include "csupport/colordefs.h"
#include "node.h"

//rtu_routing_entry *interface_listhead;
//interface_t *interface_listhead;

int interface_count = 0;
list_t *links;
list_t *interfaces;

int main ( int argc, char *argv[] )
{

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}


	if(setup_interface(argv[1]) == -1){
		printf("setup_interface() went wrong\n");
		exit(1);
	}


	//only_entry = local_routing_setup(only_interface);
	int maxfd;

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
		tvcopy = tv;
		if(select(maxfd+1, &readfds, NULL, NULL, &tvcopy) == -1){
			perror("select()");
			exit(1);
		}

		if(FD_ISSET(0, &readfds)){
			memset(command,0,CMDBUFSIZE);
			command_bytes = read(0, command, CMDBUFSIZE);

			if(command_bytes == -1){
				perror("read");
				exit(-1);
			}

			if(!strcmp("routes\n", command)){
				print_routes();
			}

			if(!strcmp("interfaces\n", command)){
				printf("%d\n", strcmp("interfaces\n", command));
				print_interfaces();
			}
			if(!strcmp("q\n", command)){
				break;
			}
		}

	}

	return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */



int setup_interface(char *filename) {

	printf(_NORMAL_"Link file -> \"%s\"\n", filename);
	links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	

	for (curr = links->head; curr != NULL; curr = curr->next) {
		
		link_t *sing = (link_t *)curr->data;
        	interface_t *inf = (interface_t *)malloc(sizeof(interface_t));
        	inf->id 	= ++interface_count;

        	inf->sockfd 	= get_socket(sing->local_phys_port, &srcaddr, SOCK_DGRAM);
        	inf->sourceaddr = srcaddr->ai_addr;

        	get_addr(sing->remote_phys_port, &destaddr, SOCK_DGRAM, 0);
		inf->destaddr = destaddr->ai_addr;

		inf->sourcevip = ntohl(sing->local_virt_ip.s_addr);
        	inf->destvip = ntohl(sing->remote_virt_ip.s_addr);
        	inf->status 	= UP;

		list_append(interfaces, inf);
	}
	
	return 0;
}



int get_socket (uint16_t portnum, struct addrinfo **source, int type) {
	
	struct addrinfo *p;
	int sockfd, yes = 1;

	if(get_addr(portnum, source, type, 1) == -1){
		printf("get_addr()\n");
		exit(1);
	}
 
	for(p = *source; p!=NULL; p=p->ai_next){
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
}	/* -----  end of function get_socket  ----- */


int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local) {
	
	int status;
	struct addrinfo hints;
	char port[32];
	sprintf(port, "%u", portnum);
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;
	
	if(local){	
		hints.ai_flags = AI_PASSIVE;
	}
	
	if ((status = getaddrinfo(NULL, port, &hints, addr)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}
	
	return 1;
}


void print_interfaces () 
{

	printf("#####INTERFACES#####\n");
	node_t *curr;
	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		char src[INET_ADDRSTRLEN];
		char dest[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->sourcevip)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->destvip)), dest, INET_ADDRSTRLEN);
		printf("Interface ID %d: using link layer socket %d to connect from:\n\tsource-%s dest-%s\n", inf->id, inf->sockfd, src, dest);
	}
	printf("####################\n");
}		/* -----  end of function print_interface  ----- */


void print_routes () 
{
}		/* -----  end of function print_routes  ----- */



