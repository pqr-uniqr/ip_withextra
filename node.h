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
#include "csupport/uthash.h"
#include "csupport/parselinks.h"

#define RECVBUFSIZE 	65536
#define CMDBUFSIZE 	1024

#define LOCALDELIVERY 	1
#define FORWARD 	0

#define UP 		1
#define DOWN 		0

#define OWN_COST	0

#define REQUEST 	1
#define RESPONSE	2

#define IPHDRSIZE sizeof(struct iphdr)

#define IP 0
#define RIP 200

typedef struct interface_t interface_t;
typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;
//typedef struct routing_table		routing_table;
//typedef struct routing_table*		routing_table_t;
//typedef struct rtu_routing_entry*	routing_entry_t;

struct interface_t{
	int id;
	int sockfd;
	struct sockaddr *sourceaddr;
	struct sockaddr *destaddr;
	uint32_t sourcevip;
	uint32_t destvip;
	bool status;
};

struct rtu_routing_entry {
	uint32_t addr;
	uint32_t cost;
	uint32_t nexthop;
	int local;
	
	UT_hash_handle hh;
};

typedef struct {
	uint16_t command;
	uint16_t num_entries;
	rtu_routing_entry entries[];
} rip_packet;

int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local);

void print_interfaces();
void print_routes();
int up_interface(int id);
int down_interface(int id);

int setup_interface(char *filename);

//functions for routing
int init_routing_table();
int route_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local);
rtu_routing_entry *find_route_entry(uint32_t id);

//temporary function for one hop routing
uint32_t route_lookup(uint32_t dest);
interface_t *inf_tosendto(uint32_t dest_vip);

//functions for making packets and sending them out
int request_routing_info(interface_t *port);
int encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet);
int send_ip(interface_t *inf, char *packet, int packetsize);
int id_ip_packet(char *packet, struct iphdr **ipheader);

