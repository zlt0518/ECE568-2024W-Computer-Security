#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

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

uint8_t *binaryConverter(char * secret_hex){
	// same assumption as before, the length is of secret_hex is fixed at 20
	int hexLength = strlen(secret_hex);
	uint8_t *byteSecret = (uint8_t *)malloc(10 * sizeof(uint8_t));
	int i = 0;
	while(i < hexLength){
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

	return byteSecret;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	// this is the number of digits for our authentication code
	int TOTP_digit = 6;
	
	// convert secret_hex to binary form
	uint8_t *binary_secret = binaryConverter(secret_hex);
	
	// instantiate the inner and outer paddings
	// let the inner and outer padding to be same size a SHA1_BLOCK
	uint8_t inner_padding[SHA1_BLOCKSIZE];
	uint8_t outer_padding[SHA1_BLOCKSIZE];

	// Referece to Lecture 12, page 22 on padding values
	// initializing all elements with 0 to avoid abnormality, except the first 10 binary secret
	for(int i = 0; i < SHA1_BLOCKSIZE; i++){
		if(i < 10){
			//printf("%x\n", binary_secret[i]);
			inner_padding[i] = binary_secret[i];
			outer_padding[i] = binary_secret[i];
			continue;
		}
		inner_padding[i] = 0;
		outer_padding[i] = 0;
	}

	// performing XOR operation in on current inner and outer pad
	for(int i = 0; i < SHA1_BLOCKSIZE; i++){
		inner_padding[i] = 0x36 ^ inner_padding[i];
		outer_padding[i] = 0x5C ^ outer_padding[i];
	}

	// handle time ==> message
	int message_size = 8;
	uint8_t message[message_size];
	uint64_t cur_time = (uint64_t) time(NULL);
	uint64_t time_span = (uint64_t) cur_time / 30;

	// printf("%x\n", time_span);
	
	int i = message_size - 1;
	while(i >= 0){
		uint8_t temp = time_span;
		message[i] = (uint8_t) (temp & 0xFF);
		time_span = time_span >> 8;
		i--;
	}

	SHA1_INFO inner_ctx;
	uint8_t inner_sha[SHA1_DIGEST_LENGTH];

	sha1_init(&inner_ctx);
	sha1_update(&inner_ctx, inner_padding, SHA1_BLOCKSIZE);
	sha1_update(&inner_ctx, message, message_size);
	sha1_final(&inner_ctx, inner_sha);

	SHA1_INFO outer_ctx;
	uint8_t outer_sha[SHA1_DIGEST_LENGTH];

	sha1_init(&outer_ctx);
	sha1_update(&outer_ctx, outer_padding, SHA1_BLOCKSIZE);
	sha1_update(&outer_ctx, inner_sha, SHA1_DIGEST_LENGTH);
	sha1_final(&outer_ctx, outer_sha);

	// reference to rfc6238, page 13, Appendix A
	
	int ofs = outer_sha[20 - 1];
	//printf("%d\n", ofs);
	ofs = ofs & 0xF;
	//printf("%d\n", ofs);

	int binary = ((outer_sha[ofs] & 0x7F) << 24) | ((outer_sha[ofs+1] & 0xFF) << 16) | ((outer_sha[ofs+2] & 0xFF) << 8) | (outer_sha[ofs+3] & 0xFF);
	//printf("%d\n", binary);
	int server_TOTP = binary % (10*10*10*10*10*10); // This 10**6 (Python Notation)

	//printf("%d\n", server_TOTP);
	// free dynamically allocated array before returning
	free(binary_secret);
	if(atoi(TOTP_string) == server_TOTP){
		return (1);
	}
	return (0);
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
