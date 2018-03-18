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
#include <sqlite3.h> 
#include <binn.h>

//Custom Functions
#include "headers/sscssl.h" //Connection functions
#include "headers/sscasymmetric.h" //keypair functions
#include "headers/sscdbfunc.h" //DB manipulation functions & B64
/*
* Application Settings
*/

#define HOST_NAME "127.0.0.1" //Server IP
#define HOST_PORT "5050" //Server Port
#define HOST_CERT "public.pem" // Server public certificate (X509 Public Cert)
#define PUB_KEY "rsapublickey.pem" //Public Key location (Will be generated if not found)
#define PRIV_KEY "rsaprivatekey.pem" //Private Key location (Will be generated if not found)
#define DB_FNAME "sscdb.db" //SQLITE Database Filename


#ifndef sscsslstruct
#define sscsslstruct
struct ssl_str{ 
	BIO *bio_obj;
	SSL *ssl_obj;
	SSL_CTX *ctx;
	const SSL_METHOD *sslmethod;
	};
#endif

const char* encryptmsg(char* username,unsigned char* message,sqlite3* db){ //returns b64 of binnobj that includes b64encryptedaeskey,aeskeylength,b64encrypedbuffer,encbuflen,b64iv,ivlen
	if(strlen((const char*)message) > 1024){
		puts("Message too long(limit 1024)");
		return NULL;	
	}
	binn* obj;
	obj = binn_object();	
	EVP_PKEY * userpubk = get_pubk_username(username,db);
	sqlite3_stmt *stmt;
	binn_object_set_str(obj,"receiver",username);
	sqlite3_prepare(db,"select username from knownusers where uid=1",-1,&stmt,NULL);
	if(sqlite3_step(stmt) == SQLITE_ROW){ //get your own username & add it to obj
		binn_object_set_str(obj,"sender",(char*)sqlite3_column_text(stmt,0));
	}
	sqlite3_finalize(stmt);

	unsigned char* ek = malloc(EVP_PKEY_size(userpubk));
	int ekl = EVP_PKEY_size(userpubk); 

	unsigned char* iv = malloc(EVP_MAX_IV_LENGTH);
	RAND_poll();  
	if(RAND_bytes(iv,EVP_MAX_IV_LENGTH) != 1){
		puts("Error getting CS-RNG for IV");	
		return NULL;	
	}
	RAND_poll();
	unsigned char*enc_buf = malloc(2000);
	int enc_len = envelope_seal(&userpubk,message,strlen((const char*)message),&ek,&ekl,iv,enc_buf); //encrypt
	if(enc_len <= 0){
		puts("Error Encrypting Message!");
		return NULL;	
	}

	binn_object_set_blob(obj,"ek",ek,ekl);
	binn_object_set_int32(obj,"ekl",ekl);
	binn_object_set_blob(obj,"enc_buf",enc_buf,enc_len);
	binn_object_set_int32(obj,"enc_len",enc_len);
	binn_object_set_int32(obj,"iv_len",EVP_MAX_IV_LENGTH);
	binn_object_set_blob(obj,"iv",iv,EVP_MAX_IV_LENGTH);
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj)); //encode w base64
	free(iv);
	free(ek);
	free(enc_buf);
	binn_free(obj);
	return (const char*)final_b64;
}

const char* decryptmsg(const char *encrypted_buffer,EVP_PKEY* privKey){ // Attempts to decrypt buffer with your private key
	if(encrypted_buffer == NULL){
		puts("Error decrypting");
		return NULL;	
	}
	binn* obj;
	obj = binn_open(base64decode(encrypted_buffer,strlen(encrypted_buffer)));
	if(obj == NULL){
		puts("Error decoding binn object.");
		return NULL;
	}	
	
	int enc_len = binn_object_int32(obj,"enc_len");

	unsigned char* enc_buf = binn_object_blob(obj,"enc_buf",&enc_len);

	int ekl = binn_object_int32(obj,"ekl");
	
	unsigned char* ek = binn_object_blob(obj,"ek",&ekl);
	
	int iv_len = binn_object_int32(obj,"iv_len");
	
	unsigned char* iv = binn_object_blob(obj,"iv",&iv_len);	
	
	unsigned char* dec_buf = malloc(2000);
	
	memset(dec_buf,0,2000);
	
	int dec_len = envelope_open(privKey,enc_buf,enc_len,ek,ekl,iv,dec_buf);
	if(dec_len <= 0){
		puts("Error Decrypting error");
		return NULL;
	}
	char *f_buf = malloc(dec_len);
	memset(f_buf,0,dec_len);
	memcpy(f_buf,dec_buf,dec_len-1);
	binn_free(obj);
	free(dec_buf);
	return (const char*)f_buf;
}


int main(void){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/simplesecurechat/server')");
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars,HOST_CERT,HOST_NAME,HOST_PORT)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		BIO_write(tls_vars->bio_obj,"12345",5);
		puts("SSL/TLS OK");
		puts("Connected to " HOST_NAME ":" HOST_PORT " using server-cert: " HOST_CERT);
	}
	else{
		puts("SSL/TLS ERROR");	
	}
	//Load Keypair From Disk
	EVP_PKEY* pubk_evp = EVP_PKEY_new();
	EVP_PKEY* priv_evp = EVP_PKEY_new();
	if(!LoadKeyPair(pubk_evp,priv_evp,PUB_KEY,PRIV_KEY)){
		puts("Loaded Keypair ERROR\nGenerating new keypair OK");
		EVP_PKEY_free(pubk_evp);
		EVP_PKEY_free(priv_evp);
		CreateKeyPair(PUB_KEY,PRIV_KEY);
		puts("Please restart the binary to load your keypair");
		return 0;
		
	}
	else {
		puts("Loaded Keypair OK");
		test_keypair(pubk_evp,priv_evp);
	}
	//Load SQLITE Database
	sqlite3 *db = initDB(DB_FNAME);
	if(db != NULL){
		puts("Loaded User OK");
	}
	else{
		puts("Loading db ERROR");
		goto CLEANUP;	
	}
	if(DBUserInit(db,PUB_KEY) != 1){
		puts("Usercheck ERROR");
		goto CLEANUP;
	}
/*
	char msg2test[200];
	char* decbuf;
	while(1){
		memset(msg2test,0,200);
		fgets(msg2test,200,stdin);
		decbuf = (char*)decryptmsg(
			encryptmsg("user",(unsigned char*)msg2test,db), // <-- This part would be done by the other person to encrypt the message, 
			priv_evp); // <-- private key to use to decrypt message
		if(decbuf != NULL){		
			puts(decbuf);
		}
		else{
			puts("error decrypting message.");
			goto CLEANUP;		
		}
	}
	*/
CLEANUP:
	
	puts("Cleaning up Objects...");	
	sqlite3_close(db);
	EVP_PKEY_free(pubk_evp);
	EVP_PKEY_free(priv_evp);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	BIO_free_all(tls_vars->bio_obj);
	SSL_CTX_free(tls_vars->ctx);
	free(tls_vars);
	tls_vars = NULL;
	return 1;
}
