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

#define RECVBUFSIZE 	65536
#define CMDBUFSIZE 	1024

#define LOCALDELIVERY 	1
#define FORWARD 	0

#define UP 		1
#define DOWN 		0

int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local);
void print_interfaces();
void print_routes();
int setup_interface(char *filename);
int init_routing_table();

typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;

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
	uint32_t cost;
	uint32_t addr;
	uint32_t nexthop;
	bool local;
};

