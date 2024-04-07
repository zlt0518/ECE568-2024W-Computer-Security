#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int hex2binary(char digit){
	// alleviate constaint of checking lower case letters
	const char *hexLib = "0123456789ABCDEF";
	int index = -1;
	//printf("The digit is %c\n", digit);
	for(int i = 0; i < strlen(hexLib); i++){
		if(digit == hexLib[i]){
			index = i;
			break;
		}
	}
	//printf("the index is %d\n", index);
	return index;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// for accountName and issuer, we need to use urlEncode()
	// for secret, we need to use base32_encode()
	const char *encodedAccountName = urlEncode(accountName);
	//printf("hello word\n");
	//printf("\nthe encoded account name is %s\n, and size of %d\n\n", encodedAccountName, strlen(encodedAccountName));

	const char *encodedIssuer = urlEncode(issuer);
	//printf("\nthe encoded issuer name is %s\n, and size of %d\n\n", encodedIssuer, strlen(encodedIssuer));

	// handling secret string
	// As mentioned in the lab handout, the length of hex secret should always be 20 by default
	// convert the secret to uint-8
	int hexLength = strlen(secret_hex);
	//printf("the lenght of the hex is %d\n", hexLength);
	
	// here, byteLength should be 10
	// considering if needed to add a constraint checking module here
	int byteLength = hexLength / 2;
	uint8_t byteSecret[byteLength];

	// there 2 nibbles in 1 byte, 1 nibble = 4 bits
	int i = 0;
	while(i < hexLength){
		//123456

		//here we handle the odd positions
		char topNibble = secret_hex[i];
		char lowNibble = secret_hex[i+1];

		int topIndex = hex2binary(topNibble);
		int lowIndex = hex2binary(lowNibble);

		assert(topIndex != -1);
		assert(lowIndex != -1);
		
		int j = i / 2;
		uint8_t bSecret = (((uint8_t)topIndex << 4) | (uint8_t)lowIndex);
		
		byteSecret[j] = bSecret;

		//printf("%c and %c\n", topNibble, lowNibble);
		i = i + 2;
	}
	/*for(int a = 0; a < 10; a++){
		printf("%x\n", byteSecret[a]);
	}*/
	// the extra +1 is used to handle string terminator
	uint8_t base32Buf[16 + 1];
	int status = base32_encode(byteSecret, 10, base32Buf, 16 + 1);
	
	char API_path[2000];
	// here we use the default 30 seconds for the period
	sprintf(API_path, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, (char *)base32Buf);
	displayQRcode(API_path);

	return (0);
}
