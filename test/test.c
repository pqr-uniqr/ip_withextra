
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

	command[command_bytes] = '\0';

	char *token;
	char *delim = " ";
	token = strtok(command, delim);
	printf("first token is %s",token);

	return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
