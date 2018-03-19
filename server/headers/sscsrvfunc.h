#ifndef SSCSRVFUNC
#define SSCSRVFUNC

#include <string.h>
#include <signal.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
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

int create_socket(int port);

void init_openssl(void);

void cleanup_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX* ctx);

#endif
