#include <stdio.h>
#include <stdlib.h>

#define INFINITY 	16
#define MAX_ROUTES	64
#define HOP_COST	1

#define NEIGHBOUR	0
#define ANONYMOUS	1

typedef struct rip_entry 	rip_entry;
typedef struct rip_packet 	rip_packet;
typedef struct burnt_inf 	burnt_inf;

struct burnt_inf {
	
	uint32_t inf;
	UT_hash_handle hh;
};

struct rip_entry {
	uint32_t addr;
	uint32_t cost;
};

struct rip_packet {
	uint16_t command;
	uint16_t num_entries;
	rip_entry entries[];
};



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
int route_table_update(rip_packet *table, uint32_t inf_from, uint32_t inf_to);

void routing_table_refresh_entries();
void routing_table_send_update();

void routing_table_take_down(int infid);


int route_table_old(rip_packet *table, uint32_t inf_from, uint32_t inf_to);
int is_own_interface(uint32_t addr);
