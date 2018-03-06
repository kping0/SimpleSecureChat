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
* Application Settings
*/

#define HOST_NAME "13.58.190.13" 
#define HOST_PORT "80"
#define HOST_CERT "public.pem"
#define PUB_KEY "rsapublickey.pem"
#define PRIV_KEY "rsaprivatekey.pem"

 /*
 *MESSAGE STRUCTURE
 *
 * SSL_TO_SERVER{ 					
 *	ENCRYPED_WITH_PUBLIC{				
 * 		SIGNED_WITH_PRIVATE{AES_SESSION_KEY}	
 * 	}
 * 	ENCRYPTED_WITH_SESSION_KEY{ 			
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

/*
* SNIPPET FROM THE OPENSSL WIKI 
*/

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
	if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, priv_key))
		return 0;
	if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return 0;
	plaintext_len = len;
	if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) return 0;
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

/*
* SNIPPET FROM THE OPENSSL WIKI
*/

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int ciphertext_len;
	int len;
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		return 0;
	if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return 0;
	ciphertext_len = len;
	if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) return 0;
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

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

void Serialize_binn_decmsg(struct _msg *msg_str,binn *obj){ /*Serializes a _msg structure to a "binn" */
	binn_object_set_int32(obj,"msg_id",msg_str->msg_id);
	binn_object_set_str(obj,"msg",msg_str->msg);
	binn_object_set_str(obj,"timestamp",msg_str->timestamp);
	binn_object_set_int32(obj,"flags",msg_str->flags);
}

void DeSerialize_binn_decmsg(struct _msg *msg_str,void *ptr_buf){ /* De-Serializes a buffer containing a "binn" obj to a _msg structure*/
	binn *obj = binn_open(ptr_buf);
	msg_str->msg_id = binn_object_int32(obj,"msg_id");
	msg_str->flags = binn_object_int32(obj,"flags");
	strncpy(msg_str->msg,binn_object_str(obj,"msg"),sizeof(msg_str->msg));
	strncpy(msg_str->timestamp,binn_object_str(obj,"timestamp"),sizeof(msg_str->timestamp));
}

int LoadKeyPair(EVP_PKEY* pubKey, EVP_PKEY* privKey){ // EVP_PKEY* pubk_evp = EVP_PKEY_new(); EVP_PKEY* priv_evp = EVP_PKEY_new(); <---- NEED TO BE SETUP BEFORE CALLING FUNCTION
	/*
	* This Function reads the Public&Private key from files into EVP_PKEY objects...
	*/
	BIO* rsa_pub_bio = BIO_new_file(PUB_KEY,"r");
	if(rsa_pub_bio == NULL){
		puts("error loading public key!"); //error checking
		return 0;	
	}
	RSA* rsa_pub = RSA_new();
	PEM_read_bio_RSAPublicKey(rsa_pub_bio,&rsa_pub,NULL,NULL);
	BIO_free(rsa_pub_bio);	
	EVP_PKEY_assign_RSA(pubKey,rsa_pub);
	
	BIO* rsa_priv_bio = BIO_new_file(PRIV_KEY,"r");
	if(rsa_priv_bio == NULL){
		puts("error loading private key!"); //error checking
		return 0;	
	}
	RSA* rsa_priv = RSA_new();
	PEM_read_bio_RSAPrivateKey(rsa_priv_bio, &rsa_priv,NULL,NULL);
	BIO_free(rsa_priv_bio);
	EVP_PKEY_assign_RSA(privKey,rsa_priv); 
	
	return 1;

}
int main(int argc,char* argv[]){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/secchatapp/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/secchatapp/server')");
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		BIO_puts(tls_vars->bio_obj,"test\n");
		puts("SSL/TLS_SUCCESS --> connected to " HOST_NAME ":" HOST_PORT " using server-cert: " HOST_CERT);
	}
	else{
		puts("SSL/TLS_ERROR");	
	}
	//Load Keypair From Disk
	EVP_PKEY* pubk_evp = EVP_PKEY_new();
	EVP_PKEY* priv_evp = EVP_PKEY_new();
	if(!LoadKeyPair(pubk_evp,priv_evp)){
		puts("Error Loading Keypair");
		EVP_PKEY_free(pubk_evp);
		EVP_PKEY_free(priv_evp);
		
	}
	else {
		puts("Loaded Keypair");
	}



	(void)ALL_cleanup(tls_vars); 
	free(tls_vars);
	tls_vars = NULL;
	return 0;
}
