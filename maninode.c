#include "parselinks.c"
#include "list.c"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "node.h"
#include "util/colordefs.h"

typedef struct sockaddr_in 	SOCKETADDR;
typedef struct Interface 	Interface;
struct Interface{
	SOCKETADDR socket_address;
};

list_t *ref;
list_t *routes;
uint32_t num_entries = 1;
void rout_table_print();

int main(int argc, char *argv[]) {
	
	// part 1
	
	char *linkFile = argv[1];
	printf(_NORMAL_"Link File -> \"%s\"\n", argv[1]);
	
	ref = parse_links(linkFile);
	
	node_t *curr;
	int i = 1;
	
	for (curr = ref->head; curr != NULL; curr = curr->next) {
		
		printf(_GREEN_"\n\tINTERFACE [%d]----- Local Physical Info -----\n", i);
		link_t *sing = (link_t *)curr->data;
		printf(_BLUE_"\tHost\t\tPort\t\tIPv4\t\n");
		printf(_BLUE_"\t%s\t%d\t\t%s\t\n"_BLUE_, sing->local_phys_host,sing->local_phys_port, inet_ntoa(sing->local_virt_ip));
		printf(_NORMAL_);
		
		printf(_RED_"\tINTERFACE [%d]----- Remote Physical Info -----\n", i++);
		printf(_BLUE_"\tHost\t\tPort\t\tIPv4\t\n");
		printf(_BLUE_"\t%s\t%d\t\t%s\t\n"_BLUE_, sing->remote_phys_host,sing->remote_phys_port, inet_ntoa(sing->remote_virt_ip));
		printf(_NORMAL_);
	}
	printf("\n");
	
	//part 2
	int sockfd;
	int yes = 1;
	link_t *tmp = (link_t *)ref->head->data;
	struct sockaddr_in addrsock;
	memset(&addrsock, 0, sizeof(addrsock));
	addrsock.sin_family = AF_INET;
	addrsock.sin_port = htons(tmp->local_phys_port);
	(addrsock.sin_addr).s_addr = INADDR_ANY;
	
	//inet_aton(inet_ntoa(tmp->local_virt_ip), &addrsock.sin_addr);
	
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ERROR : Socket");
		return -1;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("ERROR : Socket Option");
		close(sockfd);
		return -1;
	}
	if (bind(sockfd, (struct sockaddr *)&addrsock, sizeof(addrsock)) < 0) {
		perror("ERROR : Bind");
		close(sockfd);
		return -1;
	}
	
	// 2. Build Routing table
	list_init(&routes);
	struct route_entry *ent;
	
	for (curr = ref->head; curr != NULL; curr = curr->next) {
		
		
		link_t *sing = (link_t *)curr->data;
		ent = (struct route_entry *)malloc(sizeof(struct route_entry));
		ent->rtu_id = num_entries;
		ent->rtu_dst.s_addr = sing->local_virt_ip.s_addr;
		ent->rtu_cost = 0;
		ent->rtu_status = (uint8_t)1;
		list_append(routes, (void *)ent);
		
	}
	
	
	// 3 select 
	int maxfd;
	fd_set master, read_fds;
	FD_ZERO(&master);
	maxfd = sockfd + 1;
	FD_SET(sockfd, &master);
	FD_SET(0, &master);
	
	char input[BUFSIZE];
	int n;
	
	for (;;) {
		
		read_fds = master;
		
		if (select(maxfd, &master, NULL, NULL, NULL) == -1) {
			perror("Select");
			exit(4);
		}
		if (FD_ISSET(0, &read_fds)) {
			
			if (fgets(input, BUFSIZE, stdin) != NULL) {
				if (strcmp(input, "routes\n") == 0) {
					rout_table_print();
				}
			}
			
		}
		
		
	}
	
	
	
	
	
	return 0;
}

void rout_table_print() {
	
	node_t *curr;
	struct route_entry *ent;
	
	printf("Routing Table [size %d]\n", num_entries);
	
	for (curr = routes->head; curr != NULL; curr = curr->next) {
		
		ent = (struct route_entry *)curr->data;
		printf("\tRoute to %s with cost %d, \n",inet_ntoa(ent->rtu_dst), ent->rtu_cost);
		
	}
	
}


/******************* Tasks *************************
 * Netwrok A <-> B
 * 1. get the lnx file and parse it, save it in list, print it as table (DONE)
 * 2. getsocket for one local physical addrss and bind it
 * 3. Select
 * 
 */ 




