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
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include "node.h"

int interface_count = 0, maxfd;
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
		printf("setup_interface() went wrong\n");
		exit(1);
	}

	if (init_routing_table() == -1) {
		printf(_RED_"ERROR : init_routing table\n");
		exit(1);
	}

	//temporary static routing table
	list_init(&routes);
	rtu_routing_entry *a = malloc(sizeof(rtu_routing_entry));
	rtu_routing_entry *b = malloc(sizeof(rtu_routing_entry));
	rtu_routing_entry *c = malloc(sizeof(rtu_routing_entry));
	
	list_append(routes, a);
	list_append(routes, b);
	list_append(routes, c);

	struct in_addr a_vip, c_vip, ab_vip, cb_vip;
	inet_pton(AF_INET, "10.10.168.73", &a_vip);
	inet_pton(AF_INET, "10.86.3.46", &c_vip);
	inet_pton(AF_INET, "10.116.89.157", &ab_vip);
	inet_pton(AF_INET, "10.213.182.148", &cb_vip);


	if(!strcmp(argv[1],"lnx/A.lnx")){
		printf("A\n");
		a->addr = a_vip.s_addr;
		a->cost = 0;
		a->nexthop = a_vip.s_addr;
		a->local = 1;
		
		b->addr = ab_vip.s_addr;
		printf("a to b addr: %lu\n", (long unsigned int)ab_vip.s_addr);
		b->cost = 1;
		b->nexthop = ab_vip.s_addr;
		b->local = 0;

		c->addr = c_vip.s_addr;
		c->cost = 2;
		c->nexthop = ab_vip.s_addr;
		c->local = 0;
	} else if(!strcmp(argv[1], "lnx/B.lnx")){
		printf("B\n");
		rtu_routing_entry *bc = malloc(sizeof(rtu_routing_entry));
		list_append(routes, bc);

		a->addr = a_vip.s_addr;
		a->cost = 1;
		a->nexthop = a_vip.s_addr;
		a->local = 0;
		
		b->addr = ab_vip.s_addr;
		b->cost = 0;
		b->nexthop = ab_vip.s_addr;
		b->local = 1;

		c->addr = c_vip.s_addr;
		c->cost = 1;
		c->nexthop = c_vip.s_addr;
		c->local = 0;

		bc->addr = cb_vip.s_addr;
		bc->cost = 0;
		bc->nexthop = cb_vip.s_addr;
		bc->local = 1;
	} else{
		printf("C\n");
		a->addr = a_vip.s_addr;
		a->cost = 2;
		a->nexthop = cb_vip.s_addr;
		a->local = 0;
		
		b->addr = cb_vip.s_addr;
		b->cost = 1;
		b->nexthop = cb_vip.s_addr;
		b->local = 0;

		c->addr = c_vip.s_addr;
		c->cost = 0;
		c->nexthop = c_vip.s_addr;
		c->local = 1;
	} 

	//send hello out to every interface

	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		request_routing_info((interface_t *)curr->data);
	} 

	char readbuf[CMDBUFSIZE];
	char recvbuf[RECVBUFSIZE];
	char *token;
	char *delim = " ";
	int read_bytes;
	int received_bytes;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;

	while(1){
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

				printf("received %d bytes\n", received_bytes);

				struct iphdr *ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				if(id_ip_packet(recvbuf,&ipheader) == LOCALDELIVERY){
					printf("local delivery packet\n");
					if(ipheader->protocol == RIP){

						rip_packet rip;
						char *rippart = recvbuf+IPHDRSIZE;
						memcpy(&rip.command,rippart,sizeof(uint16_t));
						rippart=rippart+sizeof(uint16_t);
						memcpy(&rip.num_entries,rippart,sizeof(uint16_t));

						if(rip.command == REQUEST){
							printf("it's an rip request\n");
							//we must respond with our table
							//meaning that we should convert the table we have
							//into a RIP packet
							//anything else?
						} else {
							printf("it's an rip response\n");
							//meaning that we should update our routing table
						}

					} else if (ipheader->protocol == IP){
						//print it out(the payload)
						recvbuf[received_bytes] = '\0';
						char *payload = recvbuf+IPHDRSIZE;
						printf("payload on packet says: %s\n", payload);
					}
				} else {
					printf("packet to be forwarded\n");
					char buf[received_bytes];
					uint32_t nexthop;
					interface_t *inf;

					memcpy(buf,recvbuf,received_bytes);
					nexthop = route_lookup(ipheader->daddr);
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
				nexthop = route_lookup(destaddr.s_addr);
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
			else { // temporary send test for routing find() function
				
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


	uint32_t
route_lookup (uint32_t dest)
{
	node_t *curr;
	for(curr=routes->head;curr!=NULL;curr=curr->next){
		rtu_routing_entry *ent = (rtu_routing_entry *)curr->data;
		if(ent->addr == dest){
			printf("route found: %d\n", ent->cost);
			return ent->nexthop;
		}
	}
	printf("route not found\n");
	return -1;
}		/* -----  end of function route_lookup  ----- */



	interface_t *
inf_tosendto (uint32_t dest_vip)
{
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		if(inf->destvip == dest_vip){
			printf("interface found\n");
			return inf;
		}
	}
	printf("interface not found\n");
	return NULL;
	
}


int
request_routing_info (interface_t *inf)
{
	
	int packet_size = IPHDRSIZE + sizeof(rip_packet);
	printf("request_routing_info\n");
	//make rip request packet
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



//pack an ip header and its data
	int
encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet)
{
	printf("encapsulate_inip()\n");
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
	
	printf("checksum %d\n", checksum);
	free(h);
	return packetsize;
}		/* -----  end of function encapsulate_inip  ----- */



int
id_ip_packet (char *packet, struct iphdr **ipheader)
{
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

	printf("old checksum: %d, new checksum: %d\n", i->check, checksum);

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
}		/* -----  end of function id_ip_packet  ----- */

	int
send_ip (interface_t *inf, char *packet, int packetsize)
{
	printf("sending to interface id %d\n", inf->id);
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	printf("family: %d, data: %s\n", inf->destaddr->sa_family, inf->destaddr->sa_data);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	if(bytes_sent != packetsize){
		printf("send_ip(): %d bytes were out of %d bytes total\n", bytes_sent, packetsize);
	} else {
		printf("send_ip() successful-- %d bytes sent\n", bytes_sent);
	}

	return 0;
}		/* -----  end of function send_ip  ----- */



int init_routing_table() {
	
	routing_table = NULL;
	node_t *curr;
	
	for (curr = interfaces->head; curr != NULL; curr = curr->next) {
		interface_t *inf = (interface_t *)curr->data;
		if (route_table_add(inf->sourcevip, inf->destvip, 0, 1) == -1) {
			printf("WARNING : Entry was NOT added to routing table!\n");
			continue;
		}
	}
	return 0;
}



int route_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local) {

	rtu_routing_entry *new;
	
	HASH_FIND_INT(routing_table, &destVip, new);

	if (new == NULL) {
		new = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
		if (new == NULL) {
			printf("ERROR : Malloc new routing entry failed\n");
			return -1;
		}
		
		HASH_ADD_INT(routing_table, addr, new);
	}
	new->cost = cost;
	new->nexthop = srcVip;
	new->addr = destVip;
		
	return 0;
}


rtu_routing_entry *find_route_entry(uint32_t id) {
	
	rtu_routing_entry *entry;
	
	HASH_FIND_INT(routing_table, &id, entry);
	if (entry == NULL) {
		printf("COULD NOT FIND THE ENTRY\n");
		return NULL;
	}
	return entry;
	
}

int setup_interface(char *filename) {

	printf(_NORMAL_"Link file -> \"%s\"\n", filename);
	list_t *links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	
	
	for (curr = links->head; curr != NULL; curr = curr->next) {
		link_t *sing = (link_t *)curr->data;

		printf("setting up interface at port %d to port %d\n", sing->local_phys_port, sing->remote_phys_port);

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
}	/* -----  end of function get_socket  ----- */


int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local) {
	
	int status;
	struct addrinfo hints;
	char port[32];
	sprintf(port, "%u", portnum);
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;

	/* 
	if(local){	
		hints.ai_flags = AI_PASSIVE;
	} */
	
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
	char src[INET_ADDRSTRLEN];
	char nexthop[INET_ADDRSTRLEN];
	
	printf(_BLUE_"\t ---- ROUTING TABLE ---- \n");
	printf("\t  Address \t  Next Hop \tCost\tLocal\n");
	printf("\t |-------------|------------ |--------|------|\n");
	
    for(tmp = routing_table; tmp != NULL; tmp = (rtu_routing_entry *)(tmp->hh.next)) {
        inet_ntop(AF_INET, ((struct in_addr *)&(tmp->addr)), src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, ((struct in_addr *)&(tmp->nexthop)), nexthop, INET_ADDRSTRLEN);
        printf("\t %s\t%s\t%d\t%s\n",src, nexthop, tmp->cost, (tmp->local == 1) ? "YES" : "NO");
    }
    printf(_NORMAL_);
}		/* -----  end of function print_routes  ----- */



