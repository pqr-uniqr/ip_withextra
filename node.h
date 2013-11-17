#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>

#include "csupport/list.h"
#include "csupport/uthash.h"

#define INFINITY 	16
#define MAX_ROUTES	64
#define HOP_COST	1

#define NEIGHBOUR	0
#define ANONYMOUS	1

#define RECVBUFSIZE 	65536
#define CMDBUFSIZE 	1024
#define MAXIDENT	10

#define LOCALDELIVERY 	1
#define FORWARD 	0

#define UP 		1
#define DOWN 		0
#define OWN_COST	0
#define REQUEST 	1
#define RESPONSE	2
#define MTU		1400

#define NOOFFSET	200

#define LOCAL		1

#define IPHDRSIZE sizeof(struct iphdr)

#define IP 0
#define RIP 200

#define REFRESH_TIME	15


typedef struct rip_entry 	rip_entry;
typedef struct rip_packet 	rip_packet;
typedef struct interface_t interface_t;
typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;
typedef struct frag_ip frag_ip;
typedef struct frag_list frag_list;

struct rip_entry {
	uint32_t cost;
	uint32_t addr;
};

struct rip_packet {
	uint16_t command;
	uint16_t num_entries;
	rip_entry entries[];
};

struct interface_t{
	int id;
	int sockfd;
	struct sockaddr *sourceaddr;
	struct sockaddr *destaddr;
	uint32_t sourcevip;
	uint32_t destvip;
	bool status;

	int mtu;
};

struct rtu_routing_entry {
	uint32_t addr;
	uint32_t cost;
	uint32_t nexthop;
	int local;
	time_t ttl;
	
	UT_hash_handle hh;
};

struct frag_list{
	list_t *list;
	uint32_t list_id;
	UT_hash_handle hh;
};

struct frag_ip {
	char *data;
	int datasize;
	uint16_t offset;
	frag_ip *next;
};

int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local);

void print_interfaces();
int setup_interface(char *filename);
void print_help();

//temporary function for looking up interfaces
uint32_t route_lookup(uint32_t final_dest);
interface_t *inf_tosendto(uint32_t dest_vip);
//send out RIP request packets to every local interfaces

int min(int a, int b);
void up_interface(int id);
void down_interface(int id);
void set_mtu(int inf_num, int mtu);


//functions for making packets and sending them out
int routing_table_send_request(interface_t *port);

//take whatever info necessary and make an IP packet
int encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet, uint16_t offset, uint16_t ident);
//take the packet and send to the specified interface
int send_ip(interface_t *inf, char *packet, int packetsize);
//deencapsulate packet and put it in a malloc-ed iphdr
int id_ip_packet(char *packet, struct iphdr **ipheader);

void fragment_send(interface_t *nexthop, char **data, int datasize, uint16_t *offset, uint32_t iporigin, uint32_t ipdest, uint16_t ident);


int init_routing_table();
void print_routes();
int route_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local);
rtu_routing_entry *find_route_entry(uint32_t id);

rip_packet *routing_table_send_response(uint32_t dest, int *totsize);
void routing_table_print_packet(rip_packet *packet);

//temporary function for one hop routing
uint32_t routing_table_get_nexthop(uint32_t dest);

interface_t *inf_tosendto(uint32_t dest_vip);

int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr, int type);
int route_table_update(rip_packet *table, uint32_t inf_from);

void routing_table_refresh_entries();
void routing_table_send_update();
