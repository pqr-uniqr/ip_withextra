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
#include "csupport/colordefs.h"

#define RECVBUFSIZE 65536
#define LOCALDELIVERY 1
#define FORWARD 0

int interface_count = 0;
list_t *ref;
int parse_lxnFile(char *filename);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  
 * =====================================================================================
 */
	int
main ( int argc, char *argv[] )
{
	
	parse_lxnFile(argv[1]);
	
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


























