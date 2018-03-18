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
