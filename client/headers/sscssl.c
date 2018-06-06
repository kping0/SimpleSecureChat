
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "sscssl.h"
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

int tls_conn(struct ssl_str *tls_vars,char* hostcert,char* hostip,char* port){ //return 1 on success, 0 on error

	long chkv = 1; /*Variable for error checking*/
	/*
	*Create Variables Used By OpenSSL
	*/

	tls_vars->bio_obj = NULL;
	tls_vars->ssl_obj = NULL;
	tls_vars->ctx = NULL;
	tls_vars->sslmethod = NULL;
	tls_vars->sslmethod = SSLv23_method();
	if(!(NULL != tls_vars->sslmethod)) return 0;
	tls_vars->ctx = SSL_CTX_new(tls_vars->sslmethod); /* Generate SSL_CTX*/
	if(!(tls_vars->ctx != NULL)) return 0;

	/*
	* Set options for validation(verify against hostcert) & connection(!SSLv2 & !SSLv3 & !Compression)
	*/	

	SSL_CTX_set_verify(tls_vars->ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(tls_vars->ctx,1); 
	SSL_CTX_set_options(tls_vars->ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
	chkv = SSL_CTX_load_verify_locations(tls_vars->ctx,hostcert,NULL); /*Verify Server Certificate*/
	if(!(1 == chkv)) return 0;

	/*
	* Set connection variables 
	*/	
	
	tls_vars->bio_obj = BIO_new_ssl_connect(tls_vars->ctx);
	if(!(tls_vars->bio_obj != NULL)) return 0;
	char conndetails[40];
	sprintf(conndetails,"%s:%s",hostip,port);
	chkv = BIO_set_conn_hostname(tls_vars->bio_obj, conndetails);
	if(!(1 == chkv)) return 0;
	BIO_get_ssl(tls_vars->bio_obj, &tls_vars->ssl_obj);
	if(!(tls_vars->bio_obj != NULL)) return 0;
	chkv = SSL_set_cipher_list(tls_vars->ssl_obj,"HIGH:!aNULL:!eNULL:!PSK:!MD5:!RC4:!SHA1");
	if(!(1 == chkv)) return 0;

	/* 
	* Connect && Do Handshake
	*/

	chkv = BIO_do_connect(tls_vars->bio_obj);
	if(!(1 == chkv)) return 0;	
	chkv =BIO_do_handshake(tls_vars->bio_obj);
	if(!(1 == chkv)) return 0;

	/*
	* Check for certificate
	*/	
	
	X509* cert_test = SSL_get_peer_certificate(tls_vars->ssl_obj);
	if(cert_test){
		X509_free(cert_test);
		}
	if(NULL == cert_test){
		puts("ERR_NO_CERT");
		return 0;
	}

	return 1;
}

