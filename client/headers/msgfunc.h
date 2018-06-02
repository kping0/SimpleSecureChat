
/*
 *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
 *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SSC_MSGFUNC_H
#define SSC_MSGFUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <openssl/rand.h> 
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <sqlite3.h> 

//Custom function headers
#include "sscssl.h" //Connection functions
#include "sscasymmetric.h" //keypair functions
#include "sscdbfunc.h" //DB manipulation functions 
#include "base64.h" //Base64 Functions
#include "serialization.h" //SimpleSecureSerialization library (to replace binn)
//All configurable settings
#include "settings.h" //Modify to change configuration of SSC

/* Function taken from the OpenSSL wiki */
int sign_msg(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey); //Signs message msg with length of mlen with private key pkey, allocates signature and returns pointer to sig 

int verify_msg(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey); //Verifies message "msg" with length of "mlen" with signature "sig" and public key "pkey"

const char* encrypt_msg(char* username,unsigned char* message,EVP_PKEY* signingKey,sqlite3* db); //returns b64 of binnobj that includes b64encryptedaeskey,aeskeylength,b64encrypedbuffer,encbuflen,b64iv,ivlen

const char* decrypt_msg(const char *encrypted_buffer,EVP_PKEY* privKey,sqlite3* db); // Attempts to decrypt buffer with your private key
	
#endif /* SSC_MSGFUNC_H */
