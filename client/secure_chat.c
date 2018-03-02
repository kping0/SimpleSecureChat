#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <binn.h> //Data Serialization Library
/*
*Variables for message Caching Server
*/

#define HOST_NAME "xxx.xxx.xxx.xxx" 
#define HOST_PORT "5050"
#define HOST_CERT "public.pem"

 /*
 *MESSAGE STRUCTURE
 *
 * SSL_TO_SERVER{ 					Implimented (with certificate Validation)
 *	ENCRYPED_WITH_PUBLIC{				In progress
 * 		SIGNED_WITH_PRIVATE{AES_SESSION_KEY}	N/A
 * 	}
 * 	ENCRYPTED_WITH_SESSION_KEY{ 			N/A
 *		msg_id,
 *		msg,
 *		flags/special
 * 	}
 * }
 */
 /*
 * Structure for message.
 */
struct _msg {
	int msg_id;
	char timestamp[32];
	char msg[2048];
	int flags;
};
 /*
 *  structure used to passthrough OpenSSL objects through various functions (ex main()>>TLS_init())
 */
struct ssl_str{ 
	BIO *bio_obj;
	SSL *ssl_obj;
	SSL_CTX *ctx;
	const SSL_METHOD *sslmethod;
	int success;	
	};

int TLS_conn(struct ssl_str *tls_vars){ //return 1 on success, 0 on error

	long chkv = 1; /*Variable for error checking*/
	/*
	* Init OpenSSL Library
	*/
	
	(void)SSL_library_init(); 
	SSL_load_error_strings(); 

	/*
	*Create Variables Used By OpenSSL
	*/

	tls_vars->bio_obj = NULL;
	tls_vars->ssl_obj = NULL;
	tls_vars->ctx = NULL;
	tls_vars->sslmethod;
	tls_vars->sslmethod = SSLv23_method();
	if(!(NULL != tls_vars->sslmethod)) return 0;
	tls_vars->ctx = SSL_CTX_new(tls_vars->sslmethod); /* Generate SSL_CTX*/
	if(!(tls_vars->ctx != NULL)) return 0;

	/*
	* Set options for validation(verify against HOST_CERT) & connection(!SSLv2 & !SSLv3 & !Compression)
	*/	

	SSL_CTX_set_verify(tls_vars->ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(tls_vars->ctx,1); 
	SSL_CTX_set_options(tls_vars->ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
	chkv = SSL_CTX_load_verify_locations(tls_vars->ctx,HOST_CERT,NULL); /*Verify Server Certificate*/
	if(!(1 == chkv)) return 0;

	/*
	* Set connection variables 
	*/	
	
	tls_vars->bio_obj = BIO_new_ssl_connect(tls_vars->ctx);
	if(!(tls_vars->bio_obj != NULL)) return 0;
	chkv = BIO_set_conn_hostname(tls_vars->bio_obj, HOST_NAME ":" HOST_PORT);
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

void ALL_cleanup(struct ssl_str *tls_vars){ /*Cleanup*/
	EVP_cleanup;
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	BIO_free_all(tls_vars->bio_obj);
	SSL_CTX_free(tls_vars->ctx);
}

void Serialize_MSG(struct _msg *msg_str,binn *obj){ /*Serializes a _msg structure to a "binn" object */

	binn_object_set_int32(obj,"msg_id",msg_str->msg_id);
	binn_object_set_str(obj,"msg",msg_str->msg);
	binn_object_set_str(obj,"timestamp",msg_str->timestamp);
	binn_object_set_int32(obj,"flags",msg_str->flags);

}
void DeSerialize_MSG(struct _msg *msg_str,binn *obj){ /* De-Serializes a "binn" object to a _msg structure*/
	
	msg_str->msg_id = binn_object_int32(obj,"msg_id");
	msg_str->flags = binn_object_int32(obj,"flags");
	strncpy(msg_str->msg,binn_object_str(obj,"msg"),sizeof(msg_str->msg));
	strncpy(msg_str->timestamp,binn_object_str(obj,"timestamp"),sizeof(msg_str->timestamp));

}

int main(int argc,char* argv[]){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/secchatapp/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/secchatapp/server')");
	
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		BIO_puts(tls_vars->bio_obj,"test\n");
		puts("SSL/TLS_SUCCESS --> connected to " HOST_NAME ":" HOST_PORT " using server-cert: " HOST_CERT);
	}
	else{
		puts("SSL/TLS_ERROR");	
	}
	(void)ALL_cleanup(tls_vars); 
	free(tls_vars);
	tls_vars = NULL;
	return 0;
}




