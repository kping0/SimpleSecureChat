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

#include "settings.h"
#include "base64.h"

sqlite3* initDB(char* dbfname);

void addKnownUser(char* username,RSA *userpubkey,sqlite3 *db,char* authkey);

int getUserUID(char* username,sqlite3 *db);

int DBUserInit(sqlite3 *db,char* pkeyfn);

EVP_PKEY *get_pubk_username(char* username,sqlite3 *db);

EVP_PKEY *get_pubk_uid(int uid,sqlite3 *db);

const char* registerUserStr(sqlite3* db); //returns string you can pass to server to register your user with your public key.

const char* ServerGetUserRSA(char* username);

const char* ServerGetMessages(sqlite3* db); //Returns string that the server will interpret to send you your messages.
	
char* getMUSER(sqlite3* db); //Returns Username that has the uid=1 (your username)

char* AuthUSR(sqlite3* db);

int AddMessage(char* message, char* recipient,char* sender, sqlite3* db); //Add message to database
#endif
