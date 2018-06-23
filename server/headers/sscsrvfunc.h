
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

#ifndef SSCSRVFUNC
#define SSCSRVFUNC

#include <string.h>
#include <signal.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <assert.h>
#include <my_global.h>
#include <mysql.h>

#include "serialization.h"
#include "cstdinfo.h"
#include "settings.h"
#include "base64.h"
#include "hashing.h"
#include "simpleconfig.h"

#define UNUSED(x)((void)x)

#define MSGSND 1 //Message Send(normal message)
#define MSGREC 4 //Get new messages 
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key
#define MSGSND_RSP 5 //Server response to MSGSND
#define MSGREC_RSP 6 //Server response to MSGREC
#define REGRSA_RSP 7 //Server response to REGRSA
#define GETRSA_RSP 8 //Server response to GETRSA
#define AUTHUSR 9 //Sent from client to authenticate

extern int sock;
extern SCONFIG* config;

int create_socket(int port);

void init_openssl(void);

void cleanup_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX* ctx);

int checkforUser(char* username,MYSQL* db); 

int addUser2DB(char* username,char* b64rsa,int rsalen,char* authkey,MYSQL* db);
	
void ssc_sig_handler(int sig);

void childexit_handler(int sig);

int getUserUID(char* username,MYSQL *db);

int AddMSG2DB(MYSQL* db,char* recipient,unsigned char* message);

void exit_mysql_err(MYSQL* con); //print error message and exit

int my_mysql_query(MYSQL* con,char* query); //mysql_query() with error checking

void init_DB(void); //initalize MySQL database

MYSQL* get_handle_DB(void); //get handle to database

const char* GetEncodedRSA(char* username, MYSQL* db);

char* GetUserMessagesSRV(char* username,MYSQL* db);

SSCS_HASH* getUserAuthKeyHash(char* username,MYSQL* db);

#endif /* SSCSRVFUNC */
