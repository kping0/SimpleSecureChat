/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BASE64_H
#define BASE64_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
* Names changed from base64_encode & base64_decode to mitbase64_encode & mitbase64_decode because conflict with mysql client library function
*/
unsigned char * mitbase64_encode(const unsigned char *src, size_t len,
			      size_t *out_len);
unsigned char * mitbase64_decode(const unsigned char *src, size_t len,
			      size_t *out_len);

unsigned char* base64encode(char *src,size_t len);

unsigned char* base64decode(char *src,size_t len);

#endif /* BASE64_H */
