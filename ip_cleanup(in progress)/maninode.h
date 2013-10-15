#include <stdio.h>
#include <stdlib.h>

#define BUFSIZE			1024

struct route_entry {
	
	uint32_t		rtu_id;
	struct in_addr	rtu_dst;
	u_int16_t 		rtu_cost;
	uint8_t			rtu_status;
};
