#include <stdio.h>
#include <stdlib.h>

#define INFINITY 	16
#define MAX_ROUTES	64
#define HOP_COST	1
typedef struct rip_entry 	rip_entry;
typedef struct rip_packet 	rip_packet;

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
int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr);

void trigger_update(int sig);
