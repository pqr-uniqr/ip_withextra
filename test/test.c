
#include	<stdlib.h>
#include 	<stdio.h>
#include 	<unistd.h>
#include 	<string.h>
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  
 * =====================================================================================
 */
	int
main ( int argc, char *argv[] )
{
	char command[1024];
	int command_bytes;
	command_bytes = read(0, command, sizeof command);


	int portnum = 12;
	char port[16];
	sscanf(&portnum,"%s", port);
	sscanf(port,"%s", portnum);
	pritnf("portnummm %s\n", port);

	command[command_bytes] = '\0';

	crintf("%s\n", command);

	if(strcmp(command, "hello")){
		printf("hello detected\n");
		exit(1);
	}
	return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
