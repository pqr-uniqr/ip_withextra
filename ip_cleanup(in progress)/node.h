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

/************  Constants here ***********/
#define IPHDRSIZE sizeof(struct iphdr)

#define RECVBUFSIZE				65536
#define CMDBUFSIZE				1024
#define MAXIDENT				10

#define LOCALDELIVERY			1
#define UP						1
#define REQUEST 				1
#define LOCAL					1

#define REMOTE					0
#define IP 						0
#define FORWARD 				0
#define DOWN 					0
#define OWN_COST				0

#define RESPONSE				2

#define REFRESH_TIME			30

#define RIP 					200
#define NOOFFSET				200
#define STDIN					0
#define TIME_SEC				1
#define TIME_MIC				0
//routing constants here

#define NEIGHBOUR				0
#define HOP_COST				1
#define ANONYMOUS				1
#define INFINITY 				16
#define MAX_ROUTES				64

#define IP_VERSION				4
#define IP_IHL					5

#define TTL 					15

/*********** End of Constants ***********/

#define USAGE "Usage -> Program [file.lnx]\n"


/*********** Objects defs here ***************/

//Forwading
typedef struct interface_t 			interface_t;
typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;
typedef struct frag_ip 				frag_ip;
typedef struct frag_list 			frag_list;

//Routing
typedef struct interface_t 			interface_t;
typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;
typedef struct rip_entry 			rip_entry;
typedef struct rip_packet 			rip_packet;

/**
Interface struct.
*/
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

/**
Routing Entry structure
*/
struct rtu_routing_entry {
	
	uint32_t addr;
	uint32_t cost;
	uint32_t nexthop;
	int local;
	time_t ttl;
	
	UT_hash_handle hh; //hashable
};

/**
Fragmentation Object here
*/
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

/**
Routiting packet objects here
*/
struct rip_entry {
	uint32_t addr;
	uint32_t cost;
};

struct rip_packet {
	uint16_t command;
	uint16_t num_entries;
	rip_entry entries[];
};

/***************** Fundtion Prototypes here *******/
void validate_args(int argc, char **argv);
int setup_interface(char *filename);
int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local);
int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet, uint16_t offset, uint16_t ident);
int send_ip (interface_t *inf, char *packet, int packetsize);
void handle_ip(char recvbuf[], struct iphdr *ipheader, int received_bytes);
interface_t *inf_tosendto (uint32_t dest_vip);
void handle_forward(char recvbuf[], struct iphdr *ipheader, int received_bytes);

int init_routing_table();
int routing_table_add(uint32_t srcVip, uint32_t destVip, int cost, int local);
void update_handler(int time);
rip_packet *routing_table_wrap_packet(uint32_t dest, int *totsize);

void do_receive(interface_t *inf);
int id_ip_packet (char *packet, struct iphdr **ipheader);
void handle_rip(char recvbuf[], interface_t *i);
void handle_rip_request(interface_t *i);
int routing_table_update(rip_packet *table, uint32_t inf_otherend);
void handle_rip_response(interface_t *i, rip_packet *rip, char *rippart);
//helpers
void init_creadible_entries(list_t **credible_entries, uint32_t inf_otherend);
uint32_t routing_table_get_nexthop (uint32_t dest);

void fragment_send (interface_t *nexthop, char **data, int datasize, uint16_t *offset, uint32_t iporigin, uint32_t ipdest, uint16_t ident);
void print_help();
void routing_table_send_update();
void down_interface(int id);
void print_interfaces ();
void print_routes ();
int handle_commandline();
rip_packet *routing_table_send_response(uint32_t dest, int *totsize);
int cleanup();
void do_send(char *data);
