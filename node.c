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


int interface_count = 0, maxfd, ident = 0;
list_t  *interfaces, *routes;
fd_set masterfds;
rtu_routing_entry *routing_table;


int main ( int argc, char *argv[] )
{
	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_ZERO(&masterfds);
	FD_SET(0, &masterfds);
	struct timeval tv, tvcopy;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = 2;

	if(setup_interface(argv[1]) == -1){
		printf(_RED_"ERROR : setup_interface failed\n"_NORMAL_);
		exit(1);
	}
	
	if (init_routing_table() == -1) {
		printf(_RED_"ERROR : init_routing failed\n"_NORMAL_);
		exit(1);
	}
	
	printf("\tNode all set [ CTRL-D / CTRL-C to exit]\n");
	
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		routing_table_send_request((interface_t *)curr->data);
	}
	
	int maTime = 0;
	
	char readbuf[CMDBUFSIZE];
	char recvbuf[RECVBUFSIZE];
	char *token;
	char *delim = " ";
	int read_bytes;
	int received_bytes;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	
	int totsize;
	struct iphdr *ipheader;
	
	while(1){
		
		if (maTime++ == 5) {
			
			printf("\tTrigger Update\n");
			maTime = 0;
			ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
			
			for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			
				interface_t *i = (interface_t *)curr->data;
				rip_packet *pack = routing_table_send_response(ipheader->saddr, &totsize);
				char *packet = malloc(IPHDRSIZE + totsize);
				int maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet, -1, 0);
				send_ip(i, packet, maSize);					
				
			}
		}
		
		readfds = masterfds;
		tvcopy = tv;
		
		if(select(maxfd+1, &readfds, NULL, NULL, &tvcopy) == -1){
			perror("select()");
			exit(1);
		}
		
		for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			
			interface_t *i = (interface_t *)curr->data;
			
			if(FD_ISSET(i->sockfd, &readfds)){
				
				received_bytes = recvfrom(i->sockfd, recvbuf, RECVBUFSIZE, 0, &sender_addr, &addrlen);
				
				if(received_bytes == -1){
					perror("recvfrom()");
					exit(1);
				}

				struct iphdr *ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				
				if(id_ip_packet(recvbuf,&ipheader) == LOCALDELIVERY){
										
					if(ipheader->protocol == RIP){
						
						char *rippart = recvbuf+IPHDRSIZE;
						rip_packet *rip = malloc(sizeof(rip_packet));
						memcpy(rip,rippart,sizeof(rip_packet));
						printf(_BMAGENTA_"\tRoute Request [Command %d] [num_entries %d]\n"_NORMAL_, rip->command, rip->num_entries);
												
						if(rip->command == REQUEST){
							int totsize;
							rip_packet *pack = routing_table_send_response(ipheader->saddr, &totsize);
							char *packet = malloc(IPHDRSIZE + totsize);
							int maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet, -1, 0);
							send_ip(i, packet, maSize);							
						} else {
							int size = sizeof(rip_packet) + sizeof(rip_entry)*rip->num_entries;
							rip_packet *tmp = (rip_packet *)malloc(size);
							memcpy(tmp, rippart, size);
							printf(_RED_"\tRouting table received [Command %d] [num_entries %d]\n"_NORMAL_,tmp->command, tmp->num_entries);
							
							char xx[INET_ADDRSTRLEN];
							int j;
							
							for (j = 0; j < tmp->num_entries; j++) {
								inet_ntop(AF_INET, ((struct in_addr *)&(tmp->entries[j].addr)), xx, INET_ADDRSTRLEN);
								printf(_BBLUE_"\tEntry -> [Next Hop %s] [Cost %u]\n", xx, tmp->entries[j].cost);
							}
							
							routing_table_update(tmp, i->sourcevip, i->destvip);
							
						}
					
					} else if (ipheader->protocol == IP){
						//TODO Defragmentation happens here: check if this packet is a fragmented one
						recvbuf[received_bytes] = '\0';
						char *payload = recvbuf+IPHDRSIZE;
						printf("payload on packet says: %s (size %zu)\n", payload, strlen(payload));
					}
				} else {
					printf("packet to be forwarded\n");
					uint32_t nexthop;
					interface_t *inf;
					int offset = -1;
					char *data = recvbuf + IPHDRSIZE;
					printf("strlen(data): %zu \t%s\n", strlen(data), data);

					nexthop = routing_table_get_nexthop(ipheader->daddr);
					inf = inf_tosendto(nexthop);

					if(IPHDRSIZE + received_bytes > inf->mtu){
						fragment_send(inf, &data, strlen(data), &offset, ipheader->saddr, ipheader->daddr);
					}
	
					char *packet = malloc(IPHDRSIZE + strlen(data));
					int packetsize = encapsulate_inip(ipheader->saddr, ipheader->daddr, ipheader->protocol, data, strlen(data), &packet, offset, ident);
					send_ip(inf, packet, packetsize);
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
				int offset = -1;

				//get VIP of destination and look up next hop and its interface
				token = strtok_r(NULL,delim, &data);
				inet_pton(AF_INET, token, &destaddr);
				nexthop = routing_table_get_nexthop(destaddr.s_addr);
				inf = inf_tosendto(nexthop);

				printf(_BBLUE_"\tSENDING TO-> [NEXTHOP %s]\n", token);
		
				//get the protocol and pointer to the data
				token = strtok_r(NULL, delim, &data);

			
				printf("inf->mtu: %d\n packet size: %lu\n",inf->mtu,  IPHDRSIZE +strlen(data));
				if(IPHDRSIZE + strlen(data) > inf->mtu){
					printf("fragment send\n");
					fragment_send(inf, &data, strlen(data), &offset, inf->sourcevip, destaddr.s_addr);
				}

				//send the last packet
				char *packet = malloc(IPHDRSIZE + strlen(data));
				int packetsize = encapsulate_inip(inf->sourcevip, destaddr.s_addr, atoi(token), data, strlen(data),&packet, offset, ident);
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

	int
fragment_send (interface_t *nexthop, char **data, int datasize, int *offset, uint32_t iporigin, uint32_t ipdest)
{
	*offset = 0;

	if(ident>MAXIDENT){
		ident = 0;
	}

	int maxpayload = nexthop->mtu - IPHDRSIZE;
	char *dataend = *data + datasize;
	char buf[maxpayload];
	char *packet = malloc(IPHDRSIZE + maxpayload);
	while(*data < dataend-maxpayload){
		memcpy(buf, data, maxpayload);
		int packetsize = encapsulate_inip(iporigin, ipdest, IP, *data, maxpayload, &packet, *offset, ident);
		send_ip(nexthop, packet, packetsize);
		offset++;
		*data+=maxpayload;
	}
	ident++;
	return 0;
}

interface_t *inf_tosendto (uint32_t dest_vip) {
	
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		if(inf->sourcevip == dest_vip){
			return inf;
		}
	}
	printf("\tWarning : interface not found\n");
	return NULL;	
}

int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr) {
	
	int i;
	uint32_t addr, cost;
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	char from[INET_ADDRSTRLEN];
	rtu_routing_entry *entry;
	
	inet_ntop(AF_INET, ((struct in_addr *)&(src_addr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(dest_addr)), dest, INET_ADDRSTRLEN);
	printf(_MAGENTA_"\ttable received from [Address : %s] [next Hop : %s]\n", src, dest);
	
	for (i = 0; i < table->num_entries; i++) {
		
		addr = table->entries[i].addr;
		cost = table->entries[i].cost;
		
		inet_ntop(AF_INET, ((struct in_addr *)&(addr)), from, INET_ADDRSTRLEN);
		printf(_MAGENTA_"\tRoute Entry Receieved [Address : %s] [Cost : %d]\n", from, cost);
		
		HASH_FIND(hh, routing_table, &addr, sizeof(uint32_t), entry);
		
		if (entry == NULL) {
			
			printf(_MAGENTA_"\tCase 1 : new entry, adding\n"_NORMAL_);
			entry = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
			entry->addr = addr;
			HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), entry);
			entry->nexthop = src_addr;
			entry->cost = cost + HOP_COST;
			
		}
	}
	return 0;
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
	
	printf(_BBLUE_"\tResponding with out routing table [# routes %d] [Size %d]"_NORMAL_"\n", num_routes, size);
	
	packet = (rip_packet *)malloc(size);
	if (packet == NULL) {
		perror("Route response");
		exit(1);
	}
	
	packet->command 	= (uint16_t)RESPONSE;
	packet->num_entries = (uint16_t)num_routes; 
	
	int index = 0;
	rtu_routing_entry *info, *tmp;
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		packet->entries[index].addr = info->addr;
		packet->entries[index].cost = info->cost;
		
		index++;
	}	
	*totsize = size;
	return packet;
}

int init_routing_table() {
	
	routing_table = NULL;
	node_t *curr;
	
	printf(_MAGENTA_"\tUpdating routing table with own interfaces\n"_NORMAL_);
	for (curr = interfaces->head; curr != NULL; curr = curr->next) {
		interface_t *inf = (interface_t *)curr->data;
		if (route_table_add(inf->sourcevip, inf->sourcevip, 0, 1) == -1) { //local
			printf("WARNING : Entry was NOT added to routing table!\n");
			continue;
		}
	}
	return 0;
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
		
		inet_ntop(AF_INET, ((struct in_addr *)&(srcVip)), dest, INET_ADDRSTRLEN);
		printf(_MAGENTA_"\tFound new route to %s, cost=%d\n"_NORMAL_, dest, cost);
		
		new->addr = destVip;	
		HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), new);
	}
	new->cost = cost;
	new->nexthop = srcVip;
	new->local = local;	
	return 0;
}

int routing_table_send_request(interface_t *inf) {
	
	printf(_MAGENTA_"\tSending out requests to all our interfaces\n"_NORMAL_);
	int packet_size = IPHDRSIZE + sizeof(rip_packet);
	
	rip_packet *request = (rip_packet *) malloc(sizeof(rip_packet));
	request->command = REQUEST;
	request->num_entries = (uint16_t)0;
	
	char *packet = (char *)malloc(packet_size);
	encapsulate_inip(inf->sourcevip, inf->destvip, (uint8_t)200, request, sizeof(rip_packet), &packet, -1, 0);
	
	free(request);
	send_ip(inf, packet, packet_size);
	free(packet);
	return 0;
	
}

void routing_table_print_packet(rip_packet *packet) {
	
	char dest[INET_ADDRSTRLEN];
	int index = 0;
	
	printf("\t----------RIP packet----------\n");
	printf("\tCommand [%d] routes [%d] \n", packet->command, packet->num_entries);
	
	for (index = 0; index < packet->num_entries; index++) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(packet->entries[index].addr)), dest, INET_ADDRSTRLEN);
		printf("\tNext Hop %s Cost %d\n", dest, packet->entries[index].cost);
		
	}
}



int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet, int offset, int ident)
{
	//printf("encapsulate_inip()\n");
	struct iphdr *h=(struct iphdr *) malloc(IPHDRSIZE);
	memset(h,0,IPHDRSIZE);

	int packetsize = IPHDRSIZE + datasize;

	//fill in the header with necessary information
	h->version = 4;
	h->ihl = 5;
	h->tot_len = packetsize;
	h->protocol = protocol;
	h->saddr = src_vip;
	h->daddr = dest_vip;

	//copy header and payload to the given char*
	memcpy(*packet,h,IPHDRSIZE);
	char *datapart = *packet + IPHDRSIZE;
	memcpy(datapart, data, datasize);
	int checksum = ip_sum(*packet, h->tot_len);
	char *check = *packet + sizeof(uint8_t)*4 + sizeof(uint16_t)*3;
	memcpy(check,&checksum,sizeof(uint16_t));
	
	//printf("checksum %d\n", checksum);
	free(h);
	return packetsize;
}

int id_ip_packet (char *packet, struct iphdr **ipheader) {
	
	char *p = packet;
	struct iphdr *i = *ipheader;
	memcpy(i, p, sizeof(uint8_t));
	//p=p+sizeof(int);
	//memcpy(i->version,p, sizeof(int));
	p=p+sizeof(uint8_t)*2;
	memcpy(&(i->tot_len), p, sizeof(uint16_t));
	p=p+sizeof(uint16_t)*3+sizeof(uint8_t);
	memcpy(&(i->protocol), p, sizeof(uint8_t));
	p=p+sizeof(uint8_t); 
	memcpy(&(i->check), p, sizeof(uint16_t));
	memset(p,0,sizeof(uint16_t));
	p=p+sizeof(uint16_t);
	memcpy(&(i->saddr), p, sizeof(uint32_t));
	p=p+sizeof(uint32_t);
	memcpy(&(i->daddr), p, sizeof(uint32_t));
	int checksum = ip_sum(packet,i->tot_len);

	//printf("old checksum: %d, new checksum: %d\n", i->check, checksum);

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);

	printf("\
	version:%hd\n\
	header length (in 4-byte words):%hd\n\
	total length:%d\n\
	protocol: %hd\n\
	checksum?: %d\n\
	source: %s\n\
	destination: %s\n",i->version,i->ihl,i->tot_len,i->protocol,checksum==i->check,src,dest);

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
	//printf("sending to interface id %d\n", inf->id);
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	//printf("family: %d, data: %s\n", inf->destaddr->sa_family, inf->destaddr->sa_data);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	if(bytes_sent != packetsize){
		printf("send_ip(): %d bytes were out of %d bytes total\n", bytes_sent, packetsize);
	} else {
		//printf("send_ip() successful-- %d bytes sent\n", bytes_sent);
	}

	return 0;
}		/* -----  end of function send_ip  ----- */

rtu_routing_entry *find_route_entry(uint32_t destVip) {
	
	rtu_routing_entry *entry;
	
	HASH_FIND(hh, routing_table, &destVip, sizeof(uint32_t), entry);
	if (entry == NULL) {
		printf("COULD NOT FIND THE ENTRY\n");
		return NULL;
	}
	printf("Found the route\n");
	return entry;
	
}

int setup_interface(char *filename) {

	list_t *links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	char src[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
	
	for (curr = links->head; curr != NULL; curr = curr->next) {
		
		link_t *sing = (link_t *)curr->data;
		
		//inet_ntop(AF_INET, ((struct in_addr *)&(sing->local_virt_ip)), src, INET_ADDRSTRLEN);
		//inet_ntop(AF_INET, ((struct in_addr *)&(sing->remote_virt_ip)), dest, INET_ADDRSTRLEN);
				
	    	interface_t *inf = (interface_t *)malloc(sizeof(interface_t));
	   	inf->id 	= ++interface_count;
	   	inf->sockfd 	= get_socket(sing->local_phys_port, &srcaddr, SOCK_DGRAM);
		get_addr(sing->remote_phys_port, &destaddr, SOCK_DGRAM, 0);
		inf->destaddr = malloc(sizeof(struct sockaddr));
		inf->sourceaddr = malloc(sizeof(struct sockaddr));

		memcpy(inf->destaddr, destaddr->ai_addr, sizeof(struct sockaddr));
		memcpy(inf->sourceaddr, srcaddr->ai_addr, sizeof(struct sockaddr));
		freeaddrinfo(destaddr);
		freeaddrinfo(srcaddr);
		
		//printf("family: %d, data: %s\n", destaddr->ai_addr->sa_family, destaddr->ai_addr->sa_data);
		//printf("family: %d, data: %s\n", ((struct sockaddr *)inf->destaddr)->sa_family, ((struct sockaddr *)inf->destaddr)->sa_data);
		//printf("family: %d, data: %s\n", srcaddr->ai_addr->sa_family, srcaddr->ai_addr->sa_data);
		//printf("family: %d, data: %s\n", ((struct sockaddr *)inf->sourceaddr)->sa_family, ((struct sockaddr *)inf->sourceaddr)->sa_data);

        	inf->sourcevip = ntohl(sing->local_virt_ip.s_addr);
		inf->destvip = ntohl(sing->remote_virt_ip.s_addr);
    		inf->status = UP;

		inet_ntop(AF_INET, (struct in_addr *) &inf->sourcevip, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (struct in_addr *) &inf->destvip, dest, INET_ADDRSTRLEN);
		printf(_MAGENTA_"\tBringing up interface %s -> %s\n"_NORMAL_, src, dest);

		if(!strcmp(src, "10.116.89.157") || !strcmp(dest, "10.116.89.157")){
			printf("link A-B: MTU is 30\n");
			inf->mtu=30;
		} else {
			printf("link B-C: MTU is 25\n");
			inf->mtu=25;
		}
    		
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
	printf(_BLUE_"\t ---- ROUTING TABLE ---- \n");
	printf("\t  ID\t  SOCKFD \t SOURCE\t\tDESTINATION\n");
	printf("\t |-------|------|--------------------|--------------------|\n");
	
	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		inf = (interface_t *)curr->data;
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->sourcevip)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->destvip)), dest, INET_ADDRSTRLEN);
		printf("\t  %d\t  %d\t%s\t\t%s\n",inf->id, inf->sockfd, src, dest);
	}
}		/* -----  end of function print_interface  ----- */

void print_routes () 
{
	rtu_routing_entry *tmp;
	rtu_routing_entry *info;
	char src[INET_ADDRSTRLEN];
	char nexthop[INET_ADDRSTRLEN];
	
	printf(_BLUE_"\t ---- ROUTING TABLE ---- \n");
	printf("\t  Address \t  Next Hop \tCost\tLocal\n");
	printf("\t |-------------|------------ |--------|------|\n");
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(info->nexthop)), nexthop, INET_ADDRSTRLEN);
		printf("\t %s\t%s\t%d\t%s\n",src, nexthop, info->cost, (info->local == 1) ? "YES" : "NO");
		
	}
	
    printf(_NORMAL_);
}	

