#include "csupport/parselinks.c"
#include "csupport/list.c"
#include "csupport/ipsum.c"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <mcheck.h>
#include <signal.h>
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include "node.h"
#include "routes.h"

int interface_count = 0, maxfd;
list_t  *interfaces, *routes;
fd_set masterfds;
rtu_routing_entry *routing_table;


int main ( int argc, char *argv[]) {
	
	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}
	
	struct timeval tv, tvcopy;
	char readbuf[CMDBUFSIZE], recvbuf[RECVBUFSIZE];
	char *token, *rippart;
	char *delim = " ";
	int read_bytes, received_bytes, j , totsize;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	char xx[INET_ADDRSTRLEN];
	struct iphdr *ipheader;
	interface_t *i;
	rtu_routing_entry *ent;
	rip_packet *rip;
	node_t *curr;
	int maTime = 9;
	
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_ZERO(&masterfds);
	FD_SET(0, &masterfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = 2;

	if(setup_interface(argv[1]) == -1){
		printf("ERROR : setup_interface failed\n");
		exit(1);
	}
	
	if (init_routing_table() == -1) {
		printf("ERROR : init_routing failed\n");
		exit(1);
	}

	while(1){
		
		if (++maTime == 10) {
			maTime = 0;
			//printf("\troute: regular update.\n");
			routing_table_send_update();
		}
		
		readfds = masterfds;
		tvcopy = tv;
		
		if(select(maxfd+1, &readfds, NULL, NULL, &tvcopy) == -1){
			perror("select()");
			exit(1);
		}
		
		for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			
			i = (interface_t *)curr->data;
			
			if(FD_ISSET(i->sockfd, &readfds)){
				
				if ((received_bytes = recvfrom(i->sockfd, recvbuf, RECVBUFSIZE, 0, &sender_addr, &addrlen)) == -1) {
					perror("recvfrom()");
					exit(1);
				}
				
				ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				
				/*
				inet_ntop(AF_INET, ((struct in_addr *)&(i->sourcevip)), xx, INET_ADDRSTRLEN);
				printf(_BRED_"\tnet_recv_thread: packet received. Dest = %s\n"_NORMAL_, xx);
				* we don't know the destination of this packet yet
				*/
				
				if(id_ip_packet(recvbuf,&ipheader) == LOCALDELIVERY){
					
					//printf(_BRED_"\tnet_send: packet is to one of our own interfaces\n"_NORMAL_);
					
					if(ipheader->protocol == RIP){

						inet_ntop(AF_INET, ((struct in_addr *)&(i->destaddr)), xx, INET_ADDRSTRLEN);
						//printf("\trip_handler: Received packet from %s\n", xx);						
						inet_ntop(AF_INET, ((struct in_addr *)&(ipheader->saddr)), xx, INET_ADDRSTRLEN);
						//printf("\t, says it's from %s\n", xx);

						
						rippart = (char *)recvbuf+IPHDRSIZE;
						rip = (rip_packet *)malloc(sizeof(rip_packet));
						memcpy(rip,rippart,sizeof(rip_packet));
						
						if(ntohs(rip->command) == REQUEST){
							
							rip_packet *pack = routing_table_send_response(ipheader->saddr, &totsize);
							char *packet = malloc(IPHDRSIZE + totsize);
							int packetsize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)RIP, pack, totsize, &packet); 	
							
							send_ip(i, packet, packetsize);
						}
						else if (ntohs(rip->command) == RESPONSE) {
							int size = sizeof(rip_packet) + sizeof(rip_entry)*ntohs(rip->num_entries);
							rip_packet *tmp = (rip_packet *)malloc(size);
							memcpy(tmp, rippart, size);
							
							route_table_update(tmp, i->sourcevip);
							//routing_table_update(tmp, i->sourcevip, ipheader->saddr);
						}
					} 
					else if (ipheader->protocol == IP) {
						recvbuf[received_bytes] = '\0';
						char *payload = recvbuf+IPHDRSIZE;
						printf("payload on packet says: %s\n", payload);
					}
				} 
				else {
					printf("packet to be forwarded\n");
					char buf[received_bytes];
					uint32_t nexthop;
					interface_t *inf;
					
					memcpy(buf,recvbuf,received_bytes);
					nexthop = routing_table_get_nexthop(ipheader->daddr); 
					
					inf= inf_tosendto(nexthop); 
					send_ip(inf,buf, received_bytes);
				}
				free(ipheader);
			}
		}

		if(FD_ISSET(0, &readfds)){
			memset(readbuf, 0,CMDBUFSIZE);
			read_bytes = read(0, readbuf, CMDBUFSIZE);

			if(read_bytes == -1){
				perror("read()");
				exit(-1);
			}

			readbuf[read_bytes-1] = '\0';

			char *data; //pointer for the string part of the input
			token =strtok_r(readbuf, delim, &data);

			if(!strcmp("send", token)){
				
				struct in_addr destaddr;
				uint32_t nexthop;
				interface_t *inf;

				token = strtok_r(NULL,delim, &data);
				inet_pton(AF_INET, token, &destaddr);
				nexthop = routing_table_get_nexthop(destaddr.s_addr); 
				
				char yy[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, ((struct in_addr *)&(nexthop)), yy, INET_ADDRSTRLEN);
				//printf("\tSENDING TO-> [Next Hop %s]\n", yy);
				
				inf = inf_tosendto(nexthop);
			
				token = strtok_r(NULL, delim, &data);
				char *packet = malloc(IPHDRSIZE + strlen(data));
				int packetsize = encapsulate_inip(inf->sourcevip, destaddr.s_addr, atoi(token), data, strlen(data),&packet);
				send_ip(inf, packet, packetsize);
				free(packet);
			}

			if(!strcmp("up",token)){
				strtok(readbuf, delim);
			}
			if(!strcmp("down",token)){
				strtok(readbuf, delim);
			}
			if(!strcmp("routes", readbuf)){
				print_routes();
			}
			if(!strcmp("interfaces",readbuf)){
				print_interfaces();
			}
			if(!strcmp("q", readbuf)){
				break;
			}
		}
	}

	printf("safe exiting\n");

	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *i = (interface_t *)curr->data;
		close(i->sockfd);
		free(i->sourceaddr);
		free(i->destaddr);
		free(i);
	}

	list_free(&interfaces);

	for(curr=routes->head;curr!=NULL;curr=curr->next){
		free(curr->data);
	}

	list_free(&routes);

	return EXIT_SUCCESS;
}

int route_table_update(rip_packet *table, uint32_t inf_from) {
	
	int i, trigger = 0;
	uint32_t address, cost;
	rtu_routing_entry *entry;
	node_t *curr;
	interface_t *inf;
	char dest[INET_ADDRSTRLEN];
	
	for (i = 0; i < ntohs(table->num_entries); i++) {
		
		address = table->entries[i].addr;
		cost = ntohl(table->entries[i].cost);
		HASH_FIND(hh, routing_table, &address, sizeof(uint32_t), entry);
		
		// case (1)
		if (entry == NULL) {
			
			entry = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
			entry->addr = address;
			HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), entry);
			entry->nexthop = inf_from;
			entry->cost = cost + HOP_COST;
			
			inet_ntop(AF_INET, ((struct in_addr *)&(entry->addr)), dest, INET_ADDRSTRLEN);
			printf("\tCASE 1 : %s, cost=%d.\n", dest, entry->cost);
			trigger = 1;
			continue;
		}	
		if (entry->addr == entry->nexthop) {
			printf("\tCASE 2 : Moving on\n");
			continue;
		}
		for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			
			inf = (interface_t *)curr->data;
			if (inf->destvip == entry->addr) {
				printf("\tCASE 3 : Hey Neighbor\n");
				continue;
			}
		}
	}
	
	if(trigger){
		routing_table_send_update();
	}
	return 0;
}


//src addr should be the address of our interface
//dest addr should be the source address of the packet
int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr) {
	
	int i;
	uint32_t addr, nexthop, cost;
	char dest[INET_ADDRSTRLEN], from[INET_ADDRSTRLEN], source[INET_ADDRSTRLEN];
	rtu_routing_entry *entry;
	
	inet_ntop(AF_INET, ((struct in_addr *)&(dest_addr)), dest, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(src_addr)), source, INET_ADDRSTRLEN);
	//printf("\t [routing table update()] received src_addr = %s and ip_header %s\n", source, dest);
	
	//for every entry in B's routing table
	for (i = 0; i < ntohs(table->num_entries); i++) {
		
		addr = table->entries[i].addr;
		cost = ntohl(table->entries[i].cost);

		inet_ntop(AF_INET, ((struct in_addr *)&(addr)), dest, INET_ADDRSTRLEN);
		//printf("\tUpdate Table : Address=%s Cost is %d\n", dest, cost);
		
		inet_ntop(AF_INET, ((struct in_addr *)&(addr)), from, INET_ADDRSTRLEN);
		
		HASH_FIND(hh, routing_table, &dest_addr, sizeof(uint32_t), entry);
		
		if (entry == NULL) {
			//make a new entry
			entry = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
			entry->addr = dest_addr;
			HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), entry);
			entry->nexthop = src_addr;
			entry->cost = cost + HOP_COST;
			printf("\troute: Added new route to %s, cost=%d.\n", dest, entry->cost);
			routing_table_send_update();
		} 
		else {
			if (entry->addr == src_addr) {
				printf("IGNORE CASE\n");
				continue;
			}
			else {
				//printf("\tOld Cost (our cost) %d External cost %d\n", entry->cost, cost);
				if (entry->cost > cost+1) {
					printf("\tBetter cost found. Updating the entry [OLD COST %d] [NEW COST %d]\n", entry->cost, cost);
					entry->cost = cost;
					routing_table_send_update();
				}
			}
		}	
	}
	
	return 0;	
}
/*
 * 
 * 			if (entry->addr == src_addr) {
				printf("IGNORE CASE\n");
				continue;
			}
			else {
				/printf("\tOld Cost (our cost) %d External cost %d\n", entry->cost, cost);
				if (entry->cost > cost+1) {
					printf("\tBetter cost found. Updating the entry [OLD COST %d] [NEW COST %d]\n", entry->cost, cost);
					entry->cost = cost;
					routing_table_send_update();
				}
				else {
					printf("\tMORE COST Ignoring\n");
				}
			}
 * 
 */ 
int init_routing_table() {
	
	routing_table = NULL;
	node_t *curr;
	int i = 0;
	
	for (curr = interfaces->head; curr != NULL; curr = curr->next) {
		interface_t *inf = (interface_t *)curr->data;
		if (route_table_add(inf->sourcevip, inf->sourcevip, 0, 1) == -1) { //local
			printf("WARNING : Entry was NOT added to routing table!\n");
			continue;
		}
	}
	return 0;
}
void routing_table_send_update() {
	struct iphdr *ipheader;
	node_t *curr;
	char yyy[INET_ADDRSTRLEN];
	interface_t *i;
	rip_packet *pack;
	char *packet;
	int maSize, totsize;
	
	printf("\tSending routing table to everyone.\n");	
	ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
	
	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		
		i = (interface_t *)curr->data;
		
		inet_ntop(AF_INET, ((struct in_addr *)&(i->sourcevip)), yyy, INET_ADDRSTRLEN);
		printf("\tSending routing table to interface %s\n", yyy);
		
		inet_ntop(AF_INET, ((struct in_addr *)&(i->destvip)), yyy, INET_ADDRSTRLEN);
		printf("\tSending update to %s\n", yyy);
		
		pack = routing_table_send_response(ipheader->saddr, &totsize);
		packet = malloc(IPHDRSIZE + totsize);
		
		maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet); 	
		
		send_ip(i, packet, maSize);					
	}
	
	//printf("\tupdating routing table with own interfaces\n");
}


void routing_table_refresh_entries() {
	
	rtu_routing_entry *info, *tmp;
	char xx[INET_ADDRSTRLEN];
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), xx, INET_ADDRSTRLEN);
		info->ttl = info->ttl-1;
	}	
}

interface_t *inf_tosendto (uint32_t dest_vip) {
	
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		if(inf->sourcevip == dest_vip){
			return inf;
		}
	}
	//printf("\tWarning : interface not found\n");
	return NULL;	
}



uint32_t routing_table_get_nexthop (uint32_t dest) {
	
	rtu_routing_entry *entry;
	HASH_FIND(hh, routing_table, &dest, sizeof(uint32_t), entry);
	
	if (entry == NULL) {
		return -1;
	}
	return entry->nexthop;
}

rip_packet *routing_table_send_response(uint32_t dest, int *totsize) {
	
	rip_packet *packet;
	int num_routes = HASH_COUNT(routing_table);
	int size = sizeof(rip_packet) + sizeof(rip_entry)*num_routes;
	char addr[INET_ADDRSTRLEN], nexthop[INET_ADDRSTRLEN];
	
	packet = (rip_packet *)malloc(size);
	if (packet == NULL) {
		perror("Route response");
		exit(1);
	}
	
	packet->command 	= htons((uint16_t)RESPONSE);
	packet->num_entries = htons((uint16_t)num_routes);
	
	//printf("\troute-table has size %d\n", num_routes);
	
	int index = 0;
	rtu_routing_entry *info, *tmp;
	uint32_t cost;
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), addr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(info->nexthop)), nexthop, INET_ADDRSTRLEN);
		
		//printf("\t    cost=%d, addr=%s nexthop=%s\n", info->cost, addr, nexthop);
		
		//split hotizon poison reverse
		/*
		if (dest == info->nexthop && info->cost != 0) {
			cost = INFINITY;
		} else {
			cost = info->cost;
		}
		*/
		cost = info->cost;
		packet->entries[index].addr = info->addr;
		packet->entries[index].cost = htonl(cost);
		
		index++;
	}	
	*totsize = size;
	return packet;
}



int route_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local) {

	rtu_routing_entry *new;
	char dest[INET_ADDRSTRLEN];
	
	HASH_FIND(hh, routing_table, &destVip, sizeof(uint32_t), new);
	
	if (new == NULL) {
		new = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
		if (new == NULL) {
			printf("ERROR : Malloc new routing entry failed\n");
			return -1;
		}
		
		inet_ntop(AF_INET, ((struct in_addr *)&(destVip)), dest, INET_ADDRSTRLEN);
		//printf("\troute: Found new route to %s, cost=%d\n", dest, cost);
		
		new->addr = destVip;	
		HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), new);
		new->cost = cost;
		new->nexthop = srcVip;
		new->local = local;	
		new->ttl = REFRESH_TIME;
	}
	else {
		inet_ntop(AF_INET, ((struct in_addr *)&(destVip)), dest, INET_ADDRSTRLEN);
		//printf("\troute: Refreshing entry for %s, cost still %d\n", dest, new->cost);
		new->ttl = REFRESH_TIME;
	}
	
	return 0;
}

int routing_table_send_request(interface_t *inf) {
	
	
	int packet_size = IPHDRSIZE + sizeof(rip_packet);
	
	rip_packet *request = (rip_packet *) malloc(sizeof(rip_packet));
	request->command = REQUEST;
	request->num_entries = (uint16_t)0;
	
	char *packet = (char *)malloc(packet_size);
	encapsulate_inip(inf->sourcevip, inf->destvip, (uint8_t)200, request, sizeof(rip_packet), &packet);
	
	free(request);
	send_ip(inf, packet, packet_size);
	free(packet);
	return 0;
	
}

void routing_table_print_packet(rip_packet *packet) {
	
	char dest[INET_ADDRSTRLEN];
	int index = 0;
	rtu_routing_entry *info, *tmp;
	
	printf("\t----------RIP packet----------\n");
	printf("\tCommand [%d] routes [%d] \n", packet->command, packet->num_entries);
	
	for (index = 0; index < packet->num_entries; index++) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(packet->entries[index].addr)), dest, INET_ADDRSTRLEN);
		printf("\tNext Hop %s Cost %d\n", dest, packet->entries[index].cost);
		
	}
}



int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet) {

	struct iphdr *h=(struct iphdr *) malloc(IPHDRSIZE);
	memset(h,0,IPHDRSIZE);

	int packetsize = IPHDRSIZE + datasize;

	h->version = 4;
	h->ihl = 5;
	h->tot_len = htons(packetsize);
	h->protocol = protocol;
	h->saddr = src_vip;
	h->daddr = dest_vip;

	memcpy(*packet,h,IPHDRSIZE);
	char *datapart = *packet + IPHDRSIZE;
	memcpy(datapart, data, datasize);
	int checksum = ip_sum(*packet, IPHDRSIZE);
	char *check = *packet + sizeof(uint8_t)*4 + sizeof(uint16_t)*3;
	memcpy(check,&checksum,sizeof(uint16_t));
	
	free(h);
	return packetsize;
}

int id_ip_packet (char *packet, struct iphdr **ipheader) {
	
	char *p = packet;
	struct iphdr *i = *ipheader;
	memcpy(i, p, sizeof(uint8_t));
	p=p+sizeof(uint8_t)*2;
	memcpy(&(i->tot_len), p, sizeof(uint16_t));
	i->tot_len = ntohs(i->tot_len);
	p=p+sizeof(uint16_t)*3+sizeof(uint8_t);
	memcpy(&(i->protocol), p, sizeof(uint8_t));
	p=p+sizeof(uint8_t); 
	memcpy(&(i->check), p, sizeof(uint16_t));
	memset(p,0,sizeof(uint16_t));
	p=p+sizeof(uint16_t);
	memcpy(&(i->saddr), p, sizeof(uint32_t));
	p=p+sizeof(uint32_t);
	memcpy(&(i->daddr), p, sizeof(uint32_t));
	int checksum = ip_sum(packet,IPHDRSIZE);

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);
	/*
	printf("\
	version:%hd\n\
	header length (in 4-byte words):%hd\n\
	total length:%d\n\
	protocol: %hd\n\
	checksum?: %d\n\
	source: %s\n\
	destination: %s\n",i->version,i->ihl,i->tot_len,i->protocol,checksum==i->check,src,dest);
	*/
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf=curr->data;
		if(inf->sourcevip == i->daddr){
			return LOCALDELIVERY;
		}
	}
	return FORWARD;
}	

int send_ip (interface_t *inf, char *packet, int packetsize) {
	
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	if(bytes_sent != packetsize){
		//printf("send_ip(): %d bytes were out of %d bytes total\n", bytes_sent, packetsize);
	} else {
		//printf("send_ip() successful-- %d bytes sent\n", bytes_sent);
	}

	return 0;
}

rtu_routing_entry *find_route_entry(uint32_t destVip) {
	
	rtu_routing_entry *entry;
	
	HASH_FIND(hh, routing_table, &destVip, sizeof(uint32_t), entry);
	if (entry == NULL) {
		printf("COULD NOT FIND THE ENTRY\n");
		return NULL;
	}
	return entry;
	
}

int setup_interface(char *filename) {

	list_t *links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	
	for (curr = links->head; curr != NULL; curr = curr->next) {
		
		link_t *sing = (link_t *)curr->data;
		
		
		
	    interface_t *inf = (interface_t *)malloc(sizeof(interface_t));
	    inf->id 	= interface_count++;
	    inf->sockfd 	= get_socket(sing->local_phys_port, &srcaddr, SOCK_DGRAM);
		get_addr(sing->remote_phys_port, &destaddr, SOCK_DGRAM, 0);
		inf->destaddr = malloc(sizeof(struct sockaddr));
		inf->sourceaddr = malloc(sizeof(struct sockaddr));

		memcpy(inf->destaddr, destaddr->ai_addr, sizeof(struct sockaddr));
		memcpy(inf->sourceaddr, srcaddr->ai_addr, sizeof(struct sockaddr));
		freeaddrinfo(destaddr);
		freeaddrinfo(srcaddr);
		
        inf->sourcevip = ntohl(sing->local_virt_ip.s_addr);
	    inf->destvip = ntohl(sing->remote_virt_ip.s_addr);
    	inf->status = UP;
    	
    	inet_ntop(AF_INET, ((struct in_addr *)&(inf->sourcevip)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->destvip)), dest, INET_ADDRSTRLEN);
		//printf("\tBringing up interface %s -> %s\n", src, dest);
    	
		list_append(interfaces, inf);

		FD_SET(inf->sockfd, &masterfds);
		maxfd = inf->sockfd;
	}
	free_links(links);
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

	if(p==NULL){
		printf("socket set up failed\n");
		exit(1);
	}
	
	return sockfd;
}


int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local) {
	
	int status;
	struct addrinfo hints;
	char port[32];
	sprintf(port, "%u", portnum);
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;
	
	if ((status = getaddrinfo(NULL, port, &hints, addr)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	return 1;
}


void print_interfaces () 
{
	node_t *curr;
	interface_t *inf;
	char src[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
	printf("Interfaces:\n");
	
	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		inf = (interface_t *)curr->data;
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->sourcevip)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->destvip)), dest, INET_ADDRSTRLEN);
		printf("  %d: %s->%s. %s\n",inf->id, src, dest, (inf->status == UP) ? "UP" : "DOWN");
	}
}		

void print_routes () 
{
	rtu_routing_entry *tmp;
	rtu_routing_entry *info;
	char src[INET_ADDRSTRLEN];
	char nexthop[INET_ADDRSTRLEN];
	
	printf("Routing table:\n");
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(info->nexthop)), nexthop, INET_ADDRSTRLEN);
		printf("  Route to %s with cost %d, %s\n",src, info->cost, (info->local == 1) ? "through self" : "remote");
		
	}
	
    printf(_NORMAL_);
}	

