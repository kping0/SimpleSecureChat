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

#include "serialization.h"
#include "settings.h"
#include "base64.h"

#define UNUSED(x)((void)x)
extern int sock;

int create_socket(int port);

void init_openssl(void);

void cleanup_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX* ctx);

int checkforUser(char* username,sqlite3* db); 

int addUser2DB(char* username,char* b64rsa,int rsalen,char* authkey,sqlite3* db);
	
void sig_handler(int sig);

void childexit_handler(int sig);

int getUserUID(char* username,sqlite3 *db);

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message);

sqlite3* initDB(char* dbfname);

const char* GetEncodedRSA(char* username, sqlite3* db);

char* GetUserMessagesSRV(char* username,sqlite3* db);

char* getUserAuthKey(char* username, sqlite3* db); //gets authkey of user 'username', used for authentication

#endif
