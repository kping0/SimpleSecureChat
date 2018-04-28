
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
