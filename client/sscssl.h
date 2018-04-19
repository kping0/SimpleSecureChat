#ifndef SSCSSL_H
#define SSCSSL_H

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

#include "settings.h"

#ifndef sscsslstruct
#define sscsslstruct
struct ssl_str{ 
	BIO *bio_obj;
	SSL *ssl_obj;
	SSL_CTX *ctx;
	const SSL_METHOD *sslmethod;
	};
#endif
int TLS_conn(struct ssl_str *tls_vars,char* hostcert,char* hostip,char* port);

#endif
