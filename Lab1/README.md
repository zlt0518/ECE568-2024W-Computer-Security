Sploit 1: \
This is buffer overflow vulnerability, and the program could be exploited by overflowing the buffer. The vulnerability is caused by the strcpy() in foo() without bound checking. So, we created an attack buffer of size 124 which has a shellcode placed at the start of the attack buffer and the address of the buffer at the last 4 bytes of the attack buffer to overwrite the RA. Other bytes were filled with arbitrary letter A as place holders. Therefore, the attack is executed when the main function returns.

Sploit 2: \
This is buffer overflow vulnerability. To successfully exploit the content at RA, we need to modify the value of variables i and len to 268 and 285, respectively, to bypass the 272 length constraints and to continue overflowing the buffer. We created an attack buffer of size 280 + 5. We filled the first 45 bytes of the attack buffer with the shellcode. The 281st to 284th bytes were modified to address the buffer, and 285th byte is the string terminator. We used the env array to process the \x00 terminators.

Sploit 3: \
This is buffer overflow vulnerability. As 4 bytes of ‘A’ are appended to the buffer using sprintf() and the stack pointer points to 0x3021fe54 via the strlen(), the shellcode will begin at this address. We created an attack buffer of size 73, and filled remaining bytes with ‘\x90’. We then overwrite the 68th to 72th byte with the address of the buffer and the 73th byte as ‘\0’. The attack occurs when foo returns

Sploit 4: \
This is buffer overflow vulnerability, similar to Spoilt 2, allows exploitation by overwriting the return address pointing to our shellcode. We overwrite the "len" variable to copy our full attack string. However, the local "len" is set at 169, while it's 172 bytes from the buffer, and we could not overflow with a new length. Therefore, we overwrite the local iterator i, which is 168 bytes away from, with a smaller number. This adjustment allows more iterations of string copy, enabling the entire attack string's copy and overwriting the return address.

Sploit 5: \
This is format string vulnerability,and it could be exploited by writing to an arbitrary address with %n that writes in the bytes written. Thus, we could overwrite the return address of the foo function with the calculated address of our shell code. We could use %x to help get into the start of the format string and manipulate the overwritten value as a new return address. We use %hhn to write to each byte of the return address and construct the new address by writing to each two bytes. The attacking buffer structure [0:55] return address with dummy value,[60:109] format string and [200:244] shell code.

Sploit 6: \
Not finished
