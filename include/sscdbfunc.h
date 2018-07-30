
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
#include "msgfunc.h"
#include "base64.h"

//Message Purposes
#define MSGSND 1 //Message Send(normal message)
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key from server
#define MSGREC 4 //Get new messages
#define AUTHUSR 9 //Purpose of message is to authenticate to the server.
//Server responses to the above.
#define MSGSND_RSP 5  
#define MSGREC_RSP 6
#define REGRSA_RSP 7
#define GETRSA_RSP 8
#define AUTHUSR_RSP 10


int nsleep(long milliseconds);

sqlite3* init_db(char* dbfname);

void add_known_user(char* username,RSA *userpubkey,sqlite3 *db,char* authkey);

int get_user_uid(char* username,sqlite3 *db);

int db_user_init(sqlite3 *db,char* pkeyfn);

EVP_PKEY *get_pubk_username(char* username,sqlite3 *db);

EVP_PKEY *get_pubk_uid(int uid,sqlite3 *db);

const char* register_user_str(sqlite3* db); //returns string you can pass to server to register your user with your public key.

const char* server_get_user_rsa(char* username);

const char* server_get_messages(sqlite3* db); //Returns string that the server will interpret to send you your messages.
	
char* get_muser(sqlite3* db); //Returns Username that has the uid=1 (your username)

char* auth_usr(sqlite3* db);

void* update_messages_db(void* data);
	
/* Starts the one second update process */
void start_message_update(void* data);

/* Spawned by start_message_update,spawns an update thread every one second */ 
void* message_update_spawner(void* data);

/* Spawned by message_update_spawner */
void* update_messages_db(void* data);

#endif
