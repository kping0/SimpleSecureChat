#ifndef SSCDBFUNC_H
#define SSCDBFUNC_H

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

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

sqlite3* initDB(char* dbfname);

void addKnownUser(char* username,RSA *userpubkey,sqlite3 *db);

int getUserUID(char* username,sqlite3 *db);

int DBUserInit(sqlite3 *db,char* pkeyfn);

EVP_PKEY *get_pubk_username(char* username,sqlite3 *db);

EVP_PKEY *get_pubk_uid(int uid,sqlite3 *db);

#endif
