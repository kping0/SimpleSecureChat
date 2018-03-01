#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
/*
*Variables for message Caching Server
*
*/
#define HOST_NAME "xxx.xxx.xxx.xxx"
#define HOST_PORT "5050"
#define HOST_CERT "public.pem" //Server Certificate File

struct _msg {
	int msg_id;
	char timestamp[32];
	char msg[2048];
	int flags;
};

int main(int argc,char* argv[]){
	puts("Starting secure chat application...");
	puts("Verify the source at: ('https://www.github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/simplesecurechat/server')");
	
	/*
	* Init OpenSSL Library
	*/
	(void)SSL_library_init(); 
	SSL_load_error_strings(); 
	/*
	*Create Variables Used By OpenSSL
	*/
	BIO *bio_obj = NULL;
	SSL *ssl_obj = NULL;
	SSL_CTX *ctx = NULL;
	const SSL_METHOD *sslmethod;
	sslmethod = SSLv23_method(); /* create SSL_METHOD with SSL*/
	ctx = SSL_CTX_new(sslmethod); /* Generate SSL_CTX with SSL*/
	
	/*
	* Section Below Verifies The certificate & The !the use of SSLv2 & SSLv3 (TLS instead)
	*/	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(ctx,1); 
	SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
	SSL_CTX_load_verify_locations(ctx,HOST_CERT,NULL); /*Link to server cert.pem to check against*/
	
	/*
	* Create BIO - Set Conn HOSTNAME:PORT - Ignore outdated ciphers
	*/		
	bio_obj = BIO_new_ssl_connect(ctx);
	BIO_set_conn_hostname(bio_obj, HOST_NAME ":" HOST_PORT);
	BIO_get_ssl(bio_obj, &ssl_obj);
	SSL_set_cipher_list(ssl,"HIGH:!aNULL:!eNULL:!PSK:!MD5:!RC4:!SHA1");
	/* 
	* Connect Socket && Do Handshake
	*/
	BIO_do_connect(bio_obj);
	BIO_do_handshake(bio_obj);
	/*
	* Check if server provided Certificate	
	*/
	X509* cert = SSL_get_peer_certificate(ssl);
	if(cert){
		X509_free(cert);
		}
	if(NULL == cert){
		puts("Err LOC 1");
		return 1;
	} 
	/*
	* SSL Connection Built, main application following
	*/
	BIO_puts(bio_obj,"test\n");
	
	/*
	* CLEANUP
	*/	
	BIO_free_all(bio_obj);
	SSL_CTX_free(ctx);
	return 0;
}




