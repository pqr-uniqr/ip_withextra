


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

typedef struct{
	int id;
	int sockfd;
	struct sockaddr *sourceaddr;
	struct sockaddr *destaddr;
	uint32_t sourcevip;
	uint32_t destvip;
	bool status;
}interface_t;

typedef struct {
	uint32_t cost;
	uint32_t addr;
	uint32_t nexthop;
	time_t refreshtime;
	bool local;
}rtu_routing_entry;
