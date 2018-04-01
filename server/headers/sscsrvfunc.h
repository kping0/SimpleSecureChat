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

#include "binn.h"
#include "settings.h"

extern int sock;

extern volatile int gsigflag;

int create_socket(int port);

void init_openssl(void);

void cleanup_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX* ctx);

int checkforUser(char* username,sqlite3* db); 

int addUser2DB(char* username,char* b64rsa,int rsalen,char* authkey,sqlite3* db);
	
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

void sig_handler(int sig);

void childexit_handler(int sig);

int getUserUID(char* username,sqlite3 *db);

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message);

sqlite3* initDB(char* dbfname);

const char* GetEncodedRSA(char* username, sqlite3* db);

char* GetUserMessagesSRV(char* username,sqlite3* db);

char* getUserAuthKey(char* username, sqlite3* db); //gets authkey of user 'username', used for authentication

#endif
