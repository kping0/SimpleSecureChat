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
#include "settings.h"
#include "base64.h"

#define UNUSED(x)((void)x)
extern int sock;

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

//sqlite3* initDB(char* dbfname); /* DEPRECATED */

void exit_mysql_err(MYSQL* con); //print error message and exit

int my_mysql_query(MYSQL* con,char* query); //mysql_query() with error checking

void init_DB(void); //initalize MySQL database

MYSQL* get_handle_DB(void); //get handle to database

const char* GetEncodedRSA(char* username, MYSQL* db);

char* GetUserMessagesSRV(char* username,MYSQL* db);

char* getUserAuthKey(char* username, MYSQL* db); //gets authkey of user 'username', used for authentication

#endif
