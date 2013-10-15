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
#include <stdlib.h>
#include <stdio.h>

#include "node.h"

/****************** Globals here ****************/
int interface_count = 0;
fd_set masterfds;
int maxfd;
list_t *interfaces;
rtu_routing_entry *routing_table;
frag_list *piecekeeper;

/***************** End of Globals ***************/

int main(int argc, char *argv[])
{
	int update_time = 5;
	struct timeval tv, tvcopy;
	node_t *curr;
	interface_t *i;

	//validate the args
	validate_args(argc, argv);
	
	//setup interfaces
	setup_interface(argv[1]);

	//setup routes
	init_routing_table();
	routing_table_send_update();

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_ZERO(&masterfds);
	FD_SET(STDIN, &masterfds);
	tv.tv_sec = TIME_SEC;
	tv.tv_usec = TIME_MIC;
	maxfd = STDIN;

	//main loop
	for (;;) {
		
		readfds = masterfds;
		tvcopy = tv;

		//start the timer
		//update_handler((update_time == 0) ? 5 : update_time--);

		if(select(maxfd+1, &readfds, NULL, NULL, &tvcopy) == -1){
			perror("select()");
			exit(1);
		}

		for(curr = interfaces->head;curr!=NULL;curr=curr->next){
			i = (interface_t *)curr->data;
			if(FD_ISSET(i->sockfd, &readfds)){
				printf("about to call do_receive()\n");
				do_receive(i);
			}
		}

		if(FD_ISSET(STDIN, &readfds)){
			handle_commandline();
		}
	}

	return 0;
}

int handle_commandline() {

	char readbuf[CMDBUFSIZE];
	int read_bytes;
	char *token;
	char *delim = " ";

	memset(readbuf, 0,CMDBUFSIZE);

	if ((read_bytes = read(0, readbuf, CMDBUFSIZE)) == -1) {
		perror("read()");
		exit(-1);
	}
	readbuf[read_bytes-1] = '\0';

	char *data; //pointer for the string part of the input
	if((token =strtok_r(readbuf, delim, &data)) ==NULL){
		print_help();
	}

	if(!strcmp("send", token)){
		do_send(data);
	}
	if(!strcmp("up",token)){
		if((token = strtok_r(NULL, delim, &data)) == NULL){
			print_help();
		}
	}
	if(!strcmp("down",token)){
		if((token = strtok_r(NULL, delim, &data)) == NULL){
			print_help();
		}
		down_interface(atoi(token));
	}
	if(!strcmp("routes", token)) {
		print_routes();
	}
	if(!strcmp("interfaces", token)) {
		print_interfaces();
	}
	if(!strcmp("q", readbuf)) {
		cleanup();
	}
	if(!strcmp("mtu", readbuf)) {
		
	}
	return 0;
}

void set_mtu(int inf_num, int mtu){
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *i = curr->data;
		if(i->id == inf_num){
			i->mtu = mtu;
		}
	}
}
void do_send(char *data) {

	struct in_addr destaddr;
	uint32_t nexthop;
	interface_t *inf;
	uint16_t offset = NOOFFSET;
	char *delim = " ";
	char *token;
	int myident = 1;

	//get VIP of destination and look up next hop and its interface
	if ((token = strtok_r(NULL,delim, &data)) == NULL){
		print_help();
	}

	inet_pton(AF_INET, token, &destaddr);
	nexthop = routing_table_get_nexthop(destaddr.s_addr);
	inf = inf_tosendto(nexthop);

	//get the protocol and pointer to the data
	if((token = strtok_r(NULL, delim, &data))==NULL){
		print_help();
	}

	//Fragmentation
	if(IPHDRSIZE + strlen(data) > inf->mtu){
		offset = 0;
		fragment_send(inf, &data, strlen(data), &offset, inf->sourcevip, destaddr.s_addr, myident);
		exit(1);
	}

	//unset the M bit
	if(offset!=NOOFFSET){ offset -= 1<<13; }

	//send the last packet
	char *packet = malloc(IPHDRSIZE + strlen(data));
	int packetsize = encapsulate_inip(inf->sourcevip, destaddr.s_addr, atoi(token), data, strlen(data),&packet, offset, myident);
	send_ip(inf, packet, packetsize);
	free(packet);
	myident++;

}

int cleanup() {

	node_t *curr;

	//where all the leftover free()s are 
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
	exit(0);
}

rip_packet *routing_table_send_response(uint32_t dest, int *totsize) {
	
	rip_packet *packet;
	int num_routes, size;
	int index = 0;
	rtu_routing_entry *info, *tmp;
	uint32_t cost;

	num_routes = HASH_COUNT(routing_table);
	size = sizeof(rip_packet) + sizeof(rip_entry)*num_routes;
	
	if ((packet = (rip_packet *)malloc(size)) == NULL) {
		perror("Route response");
		exit(1);
	}
	
	packet->command = htons((uint16_t)RESPONSE);
	packet->num_entries = htons((uint16_t)num_routes);
	
	HASH_ITER(hh, routing_table, info, tmp) {
		
		//split hotizon poison reverse
		if (dest == info->nexthop && info->cost != 0) {
			//printf("poisoning route to %s\n", addr);
			cost = INFINITY;
		} else {
			cost = info->cost;
		}

		packet->entries[index].addr = info->addr;
		packet->entries[index].cost = htonl(cost);
		
		index++;
	}	
	*totsize = size;
	return packet;
}
void down_interface(int id) {
	
	node_t *curr;
	interface_t *inf;

	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		inf = curr->data;
		if(id == inf->id){
			inf->status = DOWN;
			break;
		}
	}

	rtu_routing_entry *route, *tmp;
	HASH_ITER(hh, routing_table, route, tmp){
		if(route->nexthop == inf->sourcevip || route->nexthop == inf->destvip){
			route->cost = INFINITY;
		}
	}
	routing_table_send_update();
}

void routing_table_send_update() {
	printf("send_update()\n");

	node_t *curr;
	interface_t *i;
	rip_packet *pack;
	char *packet;
	int maSize, totsize;
	
	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		i = (interface_t *)curr->data;
		if(i->status==DOWN){
			continue;
		}
		
		pack = routing_table_send_response(i->destvip, &totsize);
		packet = malloc(IPHDRSIZE + totsize);
		maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet, NOOFFSET, 0);
		send_ip(i, packet, maSize);
		free(pack);
		free(packet);
	}
}

void do_receive(interface_t *inf) {

	printf("do_receive\n");
	int received_bytes, protocol_type;
	char recvbuf[RECVBUFSIZE];
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	struct iphdr *ipheader;
	
	if ((received_bytes = recvfrom(inf->sockfd, recvbuf, RECVBUFSIZE, 0, &sender_addr, &addrlen)) == -1) {
		perror("recvfrom()");
		exit(1);
	}

	if(inf->status == DOWN) {
		return;
	}
	
	if ((ipheader = (struct iphdr *)malloc(sizeof(struct iphdr))) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	protocol_type = id_ip_packet(recvbuf,&ipheader);

	if(protocol_type == LOCALDELIVERY){

		//this packet is an RIP packet
		if(ipheader->protocol == RIP){
			handle_rip(recvbuf, inf);
		} // This is an IP packet
		else if (ipheader->protocol == IP) {
			handle_ip(recvbuf, ipheader, received_bytes);
		} // This is forwarding
		/*else {
			handle_forward(recvbuf, ipheader, received_bytes);
		} */
	} else {
		//forward
	}
	free(ipheader);

}

void handle_forward(char recvbuf[], struct iphdr *ipheader, int received_bytes) {

	uint32_t nexthop;
	interface_t *inf;
	uint16_t offset = NOOFFSET;
	char *data = recvbuf + IPHDRSIZE;
	char *packet;
	bool more;
	int myident = 1;

	//here
	nexthop = routing_table_get_nexthop(ipheader->daddr);
	inf = inf_tosendto(nexthop);

	if(received_bytes > inf->mtu){

		if ((packet = malloc(IPHDRSIZE + strlen(data))) == NULL) {
			printf("ERROR : malloc failed\n");
			exit(0);
		}
		//if this packet had already been fragmented, we must fragment it without changint the 
		//end-receiver's perception of the data(id, offset must be consistent)
		if(ipheader->id){
			
			offset= ipheader->frag_off & ~(1<<13);
			more = !!(ipheader->frag_off & (1<<13));
			
			fragment_send(inf, &data, strlen(data), &offset, ipheader->saddr, ipheader->daddr, ipheader->id);
			//unset the M bit only if this is the last fragment
			if(!more){
				offset -= 1<<13;
			}
			encapsulate_inip(ipheader->saddr, ipheader->daddr,ipheader->protocol,data, strlen(data), &packet, offset, ipheader->id);
		//this packet had not been fragmented: take it easy
		} else{
			offset = 0;
			fragment_send(inf, &data, strlen(data), &offset, ipheader->saddr, ipheader->daddr, myident);
			//unset the M bit
			offset-= 1<<13;
			encapsulate_inip(ipheader->saddr, ipheader->daddr, ipheader->protocol, data, strlen(data), &packet, offset, myident);
			myident++;
		}

		send_ip(inf, packet, strlen(data) + IPHDRSIZE);
		free(packet);
		myident++;
	}


}

//When a given packet must be broken down into n fragments, this function will send up to the n-1'th fragment
//how the last fragment is sent is up to the caller
void fragment_send (interface_t *nexthop, char **data, int datasize, uint16_t *offset, uint32_t iporigin, uint32_t ipdest, uint16_t ident){

	int maxpayload;
	char *dataend, *packet;

	*offset += 1<<13;
	maxpayload = nexthop->mtu - IPHDRSIZE;
	dataend = *data + datasize;
	if ((packet = malloc(IPHDRSIZE + maxpayload)) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	while(*data < dataend-maxpayload){

		int packetsize = encapsulate_inip(iporigin, ipdest, IP, *data, maxpayload, &packet, *offset, ident);
		send_ip(nexthop, packet, packetsize);
		*offset+=maxpayload/8;
		*data+=maxpayload;

	}
}

//A simple function that returns an interface whose source vip matches the parameter
interface_t *inf_tosendto (uint32_t dest_vip) {
	
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = (interface_t *)curr->data;
		if(inf->destvip== dest_vip){
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

void handle_ip(char recvbuf[], struct iphdr *ipheader, int received_bytes) {

	uint16_t offset, l_id;	
	bool more;
	frag_list *l;
	frag_ip *piece;

	//Defragmentation
	if(ipheader->id){

		offset = ipheader->frag_off & ~(1<<13);
		l_id = ipheader->saddr + ipheader->id;
		more = !!(ipheader->frag_off & (1<<13));
		
		HASH_FIND(hh, piecekeeper, &l_id, sizeof(uint32_t), l);

		if(l == NULL){
			if ((l= malloc(sizeof(frag_list))) == NULL) {
				printf("ERROR : malloc failed\n");
				exit(0);
			}
			l->list_id = l_id;
			list_init(&(l->list));
			HASH_ADD(hh, piecekeeper, list_id, sizeof(uint32_t), l);
		}			
		//Add this new fragment to the list
		if ((piece = (frag_ip *) malloc(sizeof(frag_ip))) == NULL) {
			printf("ERROR : malloc failed\n");
			exit(0);
		}
		piece->offset = offset;
		piece->data = malloc(received_bytes - IPHDRSIZE);
		memcpy(piece->data, recvbuf+IPHDRSIZE, received_bytes-IPHDRSIZE);
		piece->datasize = received_bytes-IPHDRSIZE;
		list_append(l->list, piece);

		//if what I just received is the last fragment (M bit set to 0), finish it up, gather the 
		//data we have so far, print it out and free everything
		if(!more){
			
			node_t *curr;
			int total_size;
			char *buffer;
			frag_ip *f;

			for(curr=l->list->head;curr!=NULL;curr=curr->next){
				frag_ip *f = (frag_ip *)curr->data;
				total_size+=f->datasize;
			}
			if ((buffer = malloc(total_size + 1)) == NULL) {
				printf("ERROR : malloc failed\n");
				exit(0);
			}
			for(curr=l->list->head;curr!=NULL;curr=curr->next){
				f = (frag_ip *)curr->data;
				memcpy(buffer+(f->offset)*8, f->data, f->datasize);
				free(f->data);
			}
			buffer[total_size+1] = '\0';
			printf("%s\n", buffer);
			free(buffer);
								
			list_free(&l->list);
			free(l);
			HASH_DEL(piecekeeper, l);

		}

	} else {
		//normal, non-fragment print
		recvbuf[received_bytes] = '\0';
		char *payload = recvbuf+IPHDRSIZE;
		printf("%s\n", payload);
	}


}

void handle_rip(char recvbuf[], interface_t *i) {
	printf("handle_rip\n");
	char *rippart;
	rip_packet *rip;
	uint16_t command_type;

	rippart = (char *)recvbuf+IPHDRSIZE;

	if ((rip = (rip_packet *)malloc(sizeof(rip_packet))) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	memcpy(rip,rippart,sizeof(rip_packet));
	command_type = ntohs(rip->command);

	if(command_type == REQUEST){
		handle_rip_request(i);
	}
	else if (command_type == RESPONSE) {
		handle_rip_response(i, rip, rippart);
	}

	free(rip);
}

void init_creadible_entries(list_t **credible_entries, uint32_t inf_otherend) {

	rtu_routing_entry *myroute, *tmp;
	uint32_t *cred;

	list_init(credible_entries);

	//look for entries which we should trust this RIP packet with
	HASH_ITER(hh, routing_table, myroute, tmp){
		//if(inf_otherend == myroute->nexthop && myroute->cost == 1){
		if(inf_otherend == myroute->nexthop){
			//the guy who just gave us the packet is a definite expert on myroute
			if ((cred= malloc(sizeof(uint32_t))) == NULL) {
				printf("ERROR : malloc failed\n");
				exit(0);
			}
			memcpy(cred, &myroute->addr, sizeof(uint32_t));
			list_append(*credible_entries, cred);
		}
	}

}

int routing_table_update(rip_packet *table, uint32_t inf_otherend) {

	printf("routing_table_update()\n");
	uint32_t address, cost;
	int i, trigger = 0;

	rtu_routing_entry *myroute, *tmp;
	list_t *credible_entries;
	node_t *curr;
	char addrbuf[INET_ADDRSTRLEN], addrbuf2[INET_ADDRSTRLEN], addrbuf3[INET_ADDRSTRLEN];
	
	init_creadible_entries(&credible_entries, inf_otherend);

	for(i=0;i<ntohs(table->num_entries);i++){
		address = table->entries[i].addr;
		cost = ntohl(table->entries[i].cost);

		HASH_FIND(hh,routing_table,&address, sizeof(uint32_t),myroute);

		if(myroute==NULL){
			routing_table_add(address, inf_otherend, (cost + HOP_COST), REMOTE);
			trigger=1;
			//continue;
		}
	}

	HASH_ITER(hh, routing_table, myroute, tmp){

		for(i=0;i<ntohs(table->num_entries);i++){

			address = table->entries[i].addr;
			cost = ntohl(table->entries[i].cost);

			//this is an advertisement for a new, better path?
			if(myroute->nexthop == inf_otherend){
				myroute->ttl = TTL;
				trigger = 1;
			}

			if(myroute->nexthop != inf_otherend && myroute->addr == address && !myroute->local && cost+HOP_COST < myroute->cost){
				myroute->nexthop = inf_otherend;
				myroute->cost = cost + HOP_COST;
				myroute->ttl = TTL;
				trigger = 1;

			} else {
				//ad for the same old path? should I believe this guy?
				for(curr=credible_entries->head;curr!=NULL;curr=curr->next){

					uint32_t *credible = (uint32_t *)curr->data;
					//only for the paths that involve him
					//if(address == *credible && myroute->addr== *credible){
					if(address == *credible && myroute->addr == address){
						
						//who do we trust to tell us that something is infinity?
						if(cost == INFINITY){
							if(myroute->cost != INFINITY){
								trigger = 1;
								myroute->ttl = TTL;
							}
							myroute->cost = INFINITY;
						}

						else if (myroute->cost != cost+HOP_COST){
							
							myroute->cost = cost+HOP_COST;
							myroute->ttl = 15;
							trigger=1;
						}
					}
				}
			}
		}
	}
	
	if(trigger){
		routing_table_send_update();
	}
	return 0;
}
/**
Adds an entry to the routing table. The source vip us used as the
next hop since it is a local interface, the address is used as the
key to the hash table and cost and local/remote is defined on the
entry.
*/
int routing_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local) {

	rtu_routing_entry *new;
	HASH_FIND(hh, routing_table, &destVip, sizeof(uint32_t), new);

	if (new == NULL) {
		
		new = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));
		if (new == NULL) {
			printf("ERROR : Malloc new routing entry failed\n");
			return -1;
		}
		new->addr = destVip;	
		HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), new);
		new->cost = cost;
		new->nexthop = srcVip;
		new->local = LOCAL;
		new->ttl = TTL;
		
	}
	return 0;
}
void handle_rip_response(interface_t *i, rip_packet *rip, char *rippart) {
	printf("handle_rip_response()\n");

	int size;
	rip_packet *packet;

	size = sizeof(rip_packet) + sizeof(rip_entry)*ntohs(rip->num_entries);
	if ((packet= (rip_packet *)malloc(size)) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	memcpy(packet, rippart, size);
	routing_table_update(packet, i->destvip);//here
	free(packet);

}

void handle_rip_request(interface_t *i) {

	rip_packet *pack;
	char *packet;
	int packetsize, totsize;
	
	//prepares the RIP packet with the given size for the flexible array
	pack = routing_table_wrap_packet(i->destvip, &totsize);

	if ((packet = malloc(IPHDRSIZE + totsize)) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}
	
	packetsize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)RIP, pack, totsize, &packet, NOOFFSET, 0);
	send_ip(i, packet, packetsize);
	free(pack);
	free(packet);

}

//takes in the next hop's interface and sends the packet to it.
int send_ip (interface_t *inf, char *packet, int packetsize) {
	printf("send_ip\n");
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));
	printf("%d\n", bytes_sent);

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	return 0;
}

//takes in necessary information (vip, protocol..) and payload buffer. Makes a packet and returns it in char **packet
int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet, uint16_t offset, uint16_t ident) {
	
	struct iphdr *h;

	if ((h =(struct iphdr *) malloc(IPHDRSIZE)) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	memset(h,0,IPHDRSIZE);
	int packetsize = IPHDRSIZE + datasize;

	h->version = IP_VERSION;
	h->ihl = IP_IHL;
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

rip_packet *routing_table_wrap_packet(uint32_t dest, int *totsize) {

	rip_packet *packet;
	int num_routes, size, index;
	uint32_t cost;
	rtu_routing_entry *info, *tmp;

	num_routes = HASH_COUNT(routing_table);
	size = sizeof(rip_packet) + sizeof(rip_entry)*num_routes;

	if ((packet = (rip_packet *)malloc(size)) == NULL) {
		printf("ERROR : malloc failed\n");
		exit(0);
	}

	packet->command = htons((uint16_t)RESPONSE);
	packet->num_entries = htons((uint16_t)num_routes);
	index = 0;
	
	HASH_ITER(hh, routing_table, info, tmp) {

		//split hotizon poison reverse
		if (dest == info->nexthop && info->cost != 0) {
			cost = INFINITY;
		} else {
			cost = info->cost;
		}
		packet->entries[index].addr = info->addr;
		packet->entries[index].cost = htonl(cost);
		index++;
	}
	*totsize = size;
	return packet;
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

	if(checksum != i->check){
		printf("checksum does not match--dropping the packet\n");
	}
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);

	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf=curr->data;
		if(inf->sourcevip == i->daddr){
			return LOCALDELIVERY;
		}
	}
	return FORWARD;
}	

/**
Updates the routing table every 5 seconds
*/
void update_handler(int time) {
	
	

}

/**
Initializes the routing table with own interfaces.
*/
int init_routing_table() {
	
	routing_table = NULL;
	node_t *curr;
	
	for (curr = interfaces->head; curr != NULL; curr = curr->next) {
		interface_t *inf = (interface_t *)curr->data;
		if (routing_table_add(inf->sourcevip, inf->sourcevip, 0, LOCALDELIVERY) == -1) { //local
			printf("WARNING : Entry was NOT added to routing table!\n");
			continue;
		}
	}
	return 0;
}

int setup_interface(char *filename) {

	list_t *links;
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	link_t *lnk;
	interface_t *inf;

	if ((links = parse_links(filename)) == NULL) {
		printf("ERROR : parse_links failed\n");
		exit(0);
	}

	for (curr = links->head; curr != NULL; curr = curr->next) {

		lnk = (link_t *)curr->data;
		if ((inf = (interface_t *)malloc(sizeof(interface_t))) == NULL) {
			printf("ERROR : malloc failed\n");
			exit(0);
		}
		inf->id = interface_count++;
		inf->sockfd = get_socket(lnk->local_phys_port, &srcaddr, SOCK_DGRAM);
		get_addr(lnk->remote_phys_port, &destaddr, SOCK_DGRAM, 0);
		
		if ((inf->destaddr = malloc(sizeof(struct sockaddr))) == NULL) {
			printf("ERROR : malloc failed\n");
			exit(0);
		}
		if((inf->sourceaddr = malloc(sizeof(struct sockaddr))) == NULL) {
			printf("ERROR : malloc failed\n");
			exit(0);	
		} 
		memcpy(inf->destaddr, destaddr->ai_addr, sizeof(struct sockaddr));
		memcpy(inf->sourceaddr, srcaddr->ai_addr, sizeof(struct sockaddr));
		freeaddrinfo(destaddr);
		freeaddrinfo(srcaddr);

		inf->sourcevip = ntohl(lnk->local_virt_ip.s_addr);
		inf->destvip = ntohl(lnk->remote_virt_ip.s_addr);
		inf->status = UP;

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
		printf("  Route to %s with cost %d, %s (%s) ttl: %d\n",src, info->cost, (info->local == 1) ? "through self" : "remote", nexthop, (int)info->ttl);
		
	}
	
    printf(_NORMAL_);
}	
/**
* Validates the command line arguments and prints out the usage
*/
void validate_args(int argc, char *argv[]) {

	if (argc < 2) {
		printf("ERROR : Invalid arguments\n");
		printf(USAGE);
	}

}

void print_help(){
	printf("commands:\n\
		send vip protocol string\n\
		routes\n\
		interfaces\n\
		up int\n\
		down int\n\
		q\n\
		mtu int int\n");
}
