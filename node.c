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
frag_list *piecekeeper;


int main ( int argc, char *argv[]) {

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}
	
	struct timeval tv, tvcopy;
	char readbuf[CMDBUFSIZE], recvbuf[RECVBUFSIZE];
	char *token, *rippart;
	char *delim = " ";
	int read_bytes, received_bytes, totsize, myident = 1;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	char xx[INET_ADDRSTRLEN];
	struct iphdr *ipheader;
	interface_t *i;
	//rtu_routing_entry *ent;
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
				ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				
				for(curr = interfaces->head;curr!=NULL;curr=curr->next){
				
					interface_t *i = (interface_t *)curr->data;

					rip_packet *pack = routing_table_send_response(i->sourcevip, &totsize);
					char *packet = malloc(IPHDRSIZE + totsize);
					int maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet, NOOFFSET, 0);
					send_ip(i, packet, maSize);					
					free(packet);
					free(pack);
			}
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
							int packetsize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)RIP, pack, totsize, &packet, NOOFFSET, 0);
							send_ip(i, packet, packetsize);
							free(pack);
							free(packet);
						}

						else if (ntohs(rip->command) == RESPONSE) {
							int size = sizeof(rip_packet) + sizeof(rip_entry)*ntohs(rip->num_entries);
							rip_packet *packet= (rip_packet *)malloc(size);
							memcpy(packet, rippart, size);
							route_table_update(packet, i->sourcevip);
							free(packet);
						}
						free(rip);

					} else if (ipheader->protocol == IP){
						//final Defragmentation 
						if(ipheader->id){
							printf("Fragmented IP packet detected\n");
							
							//get some informatio about the packet
							uint16_t offset = ipheader->frag_off & ~(1<<13);
							//uint32_t piece_num = offset*8/(i->mtu-IPHDRSIZE);
							uint32_t l_id = ipheader->saddr + ipheader->id;
							bool more = !!(ipheader->frag_off & (1<<13));
							
							printf("ident: %d offset: %d more?: %d\n", ipheader->id, offset, more);
							
							//check if we already have received other parts of this packet
							frag_list *l;
							HASH_FIND(hh, piecekeeper, &l_id, sizeof(uint32_t), l);
							if(l == NULL){
								l= malloc(sizeof(frag_list));
								l->list_id = l_id;
								list_init(&(l->list));
								HASH_ADD(hh, piecekeeper, list_id, sizeof(uint32_t), l);
							}

							//prepare the packet to be stored in side the table
							frag_ip *piece = (frag_ip *) malloc(sizeof(frag_ip));
							piece->offset = offset;
							piece->data = malloc(received_bytes - IPHDRSIZE);
							memcpy(piece->data, recvbuf+IPHDRSIZE, received_bytes-IPHDRSIZE);
							piece->datasize = received_bytes-IPHDRSIZE;
							
							//add the newest packet to the list
							list_append(l->list, piece);
							//if what I just received is the last fragment (M bit set to 0), finish it up, gather the 
							//data we have so far and print it out
							if(!more){
								node_t *curr;
								int total_size;
								for(curr=l->list->head;curr!=NULL;curr=curr->next){
									frag_ip *f = (frag_ip *)curr->data;
									total_size+=f->datasize;
								}
								char *buffer = malloc(total_size + 1);
								for(curr=l->list->head;curr!=NULL;curr=curr->next){
									frag_ip *f = (frag_ip *)curr->data;
									memcpy(buffer+(f->offset)*8, f->data, f->datasize);
								}
								buffer[total_size+1] = '\0';
								printf("%s\n", buffer);
								free(buffer);
							}
						} else {
							recvbuf[received_bytes] = '\0';
							char *payload = recvbuf+IPHDRSIZE;
							printf("%s\n", payload);
						}

					}
				}
				else {
					printf("packet to be forwarded\n");
					uint32_t nexthop;
					interface_t *inf;
					uint16_t offset = NOOFFSET;
					char *data = recvbuf + IPHDRSIZE;

					nexthop = routing_table_get_nexthop(ipheader->daddr);
					inf = inf_tosendto(nexthop);

					//fragmentation
					if(received_bytes > inf->mtu){
						printf("packet to small for this link's MTU- fragmeting\n");

						char *packet = malloc(IPHDRSIZE + strlen(data));
						if(ipheader->id){
							uint16_t offset= ipheader->frag_off & ~(1<<13);
							bool more = !!(ipheader->frag_off & (1<<13));
							
							fragment_send(inf, &data, strlen(data), &offset, ipheader->saddr, ipheader->daddr, ipheader->id);
							if(!more){offset -= 1<<13;}
							encapsulate_inip(ipheader->saddr, ipheader->daddr,ipheader->protocol,data, strlen(data), &packet, offset, ipheader->id);
							
						} else{
							offset = 0;
							fragment_send(inf, &data, strlen(data), &offset, ipheader->saddr, ipheader->daddr, myident);
							offset-= 1<<13;
							encapsulate_inip(ipheader->saddr, ipheader->daddr, ipheader->protocol, data, strlen(data), &packet, offset, myident);
							myident++;
						}

						//unset the M bit
						send_ip(inf, packet, strlen(data) + IPHDRSIZE);
						free(packet);
						myident++;
						continue;
					}

					char *packet = malloc(received_bytes);
					memcpy(packet, recvbuf, received_bytes);
					send_ip(inf, packet, received_bytes);
					free(packet);
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
				uint16_t offset = NOOFFSET;

				//get VIP of destination and look up next hop and its interface
				token = strtok_r(NULL,delim, &data);
				if(token == NULL){
					printf("usage: send vip proto string\n");
				}

				inet_pton(AF_INET, token, &destaddr);
				nexthop = routing_table_get_nexthop(destaddr.s_addr);
				inf = inf_tosendto(nexthop);

				printf(_BBLUE_"\tSENDING TO-> [NEXTHOP %s]\n", token);
		
				//get the protocol and pointer to the data
				token = strtok_r(NULL, delim, &data);
				if(token == NULL){
					printf("usage: send vip proto string\n");
				}
				//Fragmentation
				if(IPHDRSIZE + strlen(data) > inf->mtu){
					offset = 0;
					fragment_send(inf, &data, strlen(data), &offset, inf->sourcevip, destaddr.s_addr, myident);
				}

				//unset the M bit
				if(offset!=NOOFFSET){offset -= 1<<13;}

				//send the last packet
				char *packet = malloc(IPHDRSIZE + strlen(data));
				int packetsize = encapsulate_inip(inf->sourcevip, destaddr.s_addr, atoi(token), data, strlen(data),&packet, offset, myident);
				send_ip(inf, packet, packetsize);
				free(packet);
				myident++;
			}

			if(!strcmp("up",token)){
				strtok(NULL, delim);
			}
			if(!strcmp("down",token)){
				strtok(NULL, delim);
			}
			if(!strcmp("routes", token)){
				print_routes();
			}
			if(!strcmp("interfaces", token)){
				print_interfaces();
			}
			if(!strcmp("q", readbuf)){
				break;
			}
			if(!strcmp("mtu", readbuf)){

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

	rtu_routing_entry *entry, *temp;
	HASH_ITER(hh, routing_table, entry, temp){
		HASH_DEL(routing_table, entry);
		free(entry);
	}

	frag_list *list, *tmp;
	HASH_ITER(hh, piecekeeper, list, tmp) {
		for(curr=list->list->head;curr!=NULL;curr=curr->next){
			frag_ip *f = (frag_ip *)curr->data;
			free(f->data);
		}
		list_free(&list->list);
		HASH_DEL(piecekeeper, list);
		free(list);
	}

	return EXIT_SUCCESS;
}


void fragment_send (interface_t *nexthop, char **data, int datasize, uint16_t *offset, uint32_t iporigin, uint32_t ipdest, uint16_t ident){
	*offset += 1<<13;
	int maxpayload = nexthop->mtu - IPHDRSIZE;
	char *dataend = *data + datasize;
	char *packet = malloc(IPHDRSIZE + maxpayload);

	while(*data < dataend-maxpayload){
		int packetsize = encapsulate_inip(iporigin, ipdest, IP, *data, maxpayload, &packet, *offset, ident);
		send_ip(nexthop, packet, packetsize);
		*offset+=maxpayload/8;
		*data+=maxpayload;
	}
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
			//printf("\tCASE 1 : %s, cost=%d.\n", dest, entry->cost);
			trigger = 1;
			continue;
		}	
		if (entry->addr == entry->nexthop) {
			//printf("\tCASE 2 : Moving on\n");
			continue;
		}
		for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			
			inf = (interface_t *)curr->data;
			if (inf->destvip == entry->addr) {
				//printf("\tCASE 3 : Hey Neighbor\n");
				continue;
			}
		}
	}
	
	if(trigger){
		routing_table_send_update();
	}
	return 0;
}


int init_routing_table() {
	
	routing_table = NULL;
	node_t *curr;
	
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
		maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet, NOOFFSET, 0);
		send_ip(i, packet, maSize);
		free(pack);
		free(packet);
	}
	free(ipheader);
}


void routing_table_refresh_entries() {
	
	rtu_routing_entry *info, *tmp;
	char xx[INET_ADDRSTRLEN];
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), xx, INET_ADDRSTRLEN);
		info->ttl = info->ttl-1;
	}	
}


//A simple function that returns an interface whose source vip matches the parameter
interface_t *inf_tosendto (uint32_t dest_vip) {
	
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		if(inf->sourcevip == dest_vip){
			return inf;
		}
	}
	return NULL;	
}



//a simple function that lets the forwarding portion query the routing table for the next hop
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
	
	printf(_BBLUE_"\tResponding with our routing table [# routes %d] [Size %d]"_NORMAL_"\n", num_routes, size);
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
	encapsulate_inip(inf->sourcevip, inf->destvip, (uint8_t)200, request, sizeof(rip_packet), &packet, NOOFFSET, 0);
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


//takes in necessary information (vip, protocol..) and payload buffer. Makes a packet and returns it in char **packet
int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet, uint16_t offset, uint16_t ident)
{
	struct iphdr *h=(struct iphdr *) malloc(IPHDRSIZE);
	memset(h,0,IPHDRSIZE);

	int packetsize = IPHDRSIZE + datasize;

	h->version = 4;
	h->ihl = 5;
	h->tot_len = htons(packetsize);
	h->protocol = protocol;
	h->saddr = src_vip;
	h->daddr = dest_vip;

	//for fragmentation
	if(offset!=NOOFFSET){
		h->id = ident;
		h->frag_off = offset;
	}

	memcpy(*packet,h,IPHDRSIZE);
	char *datapart = *packet + IPHDRSIZE;
	memcpy(datapart, data, datasize);
	int checksum = ip_sum(*packet, IPHDRSIZE);
	char *check = *packet + sizeof(uint8_t)*4 + sizeof(uint16_t)*3;
	memcpy(check,&checksum,sizeof(uint16_t));
	
	free(h);
	return packetsize;
}


//steps through the received IP packet and packs it back into a struct ip hdr
//also returns a value suggesting whether the packet identified is to be delivered locally or forwarded
int id_ip_packet (char *packet, struct iphdr **ipheader) {
	
	char *p = packet;
	struct iphdr *i = *ipheader;
	memcpy(i, p, sizeof(uint8_t));
	p=p+sizeof(uint8_t)*2;
	memcpy(&(i->tot_len), p, sizeof(uint16_t));
	i->tot_len = ntohs(i->tot_len);
	p=p+sizeof(uint16_t);
	memcpy(&(i->id), p, sizeof(uint16_t));
	p=p+sizeof(uint16_t);
	memcpy(&(i->frag_off),p, sizeof(uint16_t));
	p=p+sizeof(uint16_t)+sizeof(uint8_t);
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


//takes in the next hop's interface and sends the packet to it.
int send_ip (interface_t *inf, char *packet, int packetsize) {
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
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

//reads from the passed in lnx file and make interfaces based on each line.
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
	   	inf->id 	= ++interface_count;
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
		inf->mtu = MTU;

		inet_ntop(AF_INET, (struct in_addr *) &inf->sourcevip, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (struct in_addr *) &inf->destvip, dest, INET_ADDRSTRLEN);
		printf(_MAGENTA_"\tBringing up interface %s -> %s\n"_NORMAL_, src, dest);

		/* for fragmentation testing purposes
		if(!strcmp(src, "10.116.89.157") || !strcmp(dest, "10.116.89.157")){
			printf("link A-B: MTU is 36\n");
			inf->mtu=36;
		} else {
			printf("link B-C: MTU is 28\n");
			inf->mtu=28;
		} */
    		
		list_append(interfaces, inf);

		FD_SET(inf->sockfd, &masterfds);
		maxfd = inf->sockfd;
	}

	free_links(links);
	return 0;
}



//does get_addr and all that to set up a socket and returns its fd number to the caller
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


//wrapper function for get_addrinfo() and its steps
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


//as name suggests
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

//as name suggests
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

