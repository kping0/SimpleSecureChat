
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

#ifndef SSCASYMMETRIC_H
#define SSCASYMMETRIC_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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

#include "settings.h"

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext);

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext);

int LoadKeyPair(EVP_PKEY* pubKey, EVP_PKEY* privKey,char* path4pubkey,char* path4privkey);

void CreateKeyPair(char* path4pubkey,char* path4privkey,int keysize);

int test_keypair(EVP_PKEY* pubk_evp,EVP_PKEY* priv_evp);
#endif
