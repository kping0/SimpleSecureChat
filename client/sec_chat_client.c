#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

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

//Custom function headers
#include "headers/binn.h" //Binn library 
#include "headers/sscssl.h" //Connection functions
#include "headers/sscasymmetric.h" //keypair functions
#include "headers/sscdbfunc.h" //DB manipulation functions & B64

//All configurable settings
#include "headers/settings.h" //Modify to change configuration of SSC

//Prototype functions
const char* encryptmsg(char* username,unsigned char* message,sqlite3* db); //encrypt buffer message with a public key fetched (index username) from the sqlite3 db (returns encryped buffer)
const char* decryptmsg(const char *encrypted_buffer,EVP_PKEY* privKey); // Attempts to decrypt buffer with your private key

//Startpoint
int main(void){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/simplesecurechat/server')");
	#ifdef SSC_VERIFY_VARIABLES
	puts("SSC_VERIFY_VARIABLES IS DEFINED.");
	#endif
	#ifndef SSC_VERIFY_VARIABLES
	puts("SSC_VERIFY_VARIABLES IS NOT DEFINED");
	#endif
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars,HOST_CERT,HOST_NAME,HOST_PORT)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
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
		printf("Loaded Keypair ERROR\nGenerating %i bit Keypair, this can take up to 5 minutes!\n",KEYSIZE);
		EVP_PKEY_free(pubk_evp);
		EVP_PKEY_free(priv_evp);
		CreateKeyPair(PUB_KEY,PRIV_KEY,KEYSIZE);
		puts("Generated Keypair\nPlease restart the binary to load your keypair");
		return 0;
	}
	else {
		puts("Loaded Keypair OK");
	#ifdef SSC_VERIFY_VARIABLES
		assert(test_keypair(pubk_evp,priv_evp) == 1);
	#endif
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
//register your user
	printf("Your username is: %s, trying to register it with the server\n",getMUSER(db));
	char* regubuf = (char*)registerUserStr(db);
	#ifdef SSC_VERIFY_VARIABLES
	assert(regubuf != NULL && strlen(regubuf) > 0);
	#endif
	BIO_write(tls_vars->bio_obj,regubuf,strlen(regubuf)); 
	free(regubuf);

//Authenticate USER
	char* authmsg = AuthUSR(db);
	printf("Trying to authenticate your user\n");
	#ifdef SSC_VERIFY_VARIABLES
	assert(authmsg != NULL && strlen(authmsg) > 0);
	#endif
	BIO_write(tls_vars->bio_obj,authmsg,strlen(authmsg));
	free(authmsg);
	char* decbuf;
	char* encbuf;
	//Buffers for TLS connection
	char* rxbuf = malloc(4096);
	char* txbuf = malloc(4096);
	//Stdin Buffers
	char* inbuf = malloc(1024);
	char* inbuf2 = malloc(1024);
//
// This is a very Quickly written UI.
//

	while(1){ //to be replaced by GUI
		puts("Options: Send message(1),AddUser(2),Get messages(3)");
		int options;
		options = fgetc(stdin);
		while(fgetc(stdin) != '\n'){} //Clear STDIN
		switch(options){
			case '1': //If User wants to send a message do:
				memset(inbuf,0,1024);
				memset(inbuf2,0,1024);
				printf("recipient name: ");
				fgets(inbuf,1024,stdin);
				printf("Message to user: ");
				fgets(inbuf2,1024,stdin);
				//sending user
				encbuf = (char*)encryptmsg(inbuf,(unsigned char*)inbuf2,db); //"user" would be the receiving username
				#ifdef SSC_VERIFY_VARIABLES
				assert(encbuf != NULL);
				#endif	
				printf("Encrypted message: %s with length: %d\n",encbuf,(int)strlen(encbuf));
				BIO_write(tls_vars->bio_obj,encbuf,strlen(encbuf));
				free(encbuf);
				encbuf = NULL;
				break;

			case '2': //If User wants to add another user do:
				memset(inbuf,0,1024);
				puts("Username for public key to get:");
				fgets(inbuf,1024,stdin);

				char* gtrsa64 = (char*)ServerGetUserRSA(inbuf);		
				puts(gtrsa64);
				BIO_write(tls_vars->bio_obj,gtrsa64,strlen(gtrsa64));
				free(gtrsa64);
				gtrsa64 = NULL;
				memset(rxbuf,0,4096);
				BIO_read(tls_vars->bio_obj,rxbuf,4096);
				if(strcmp(rxbuf,"GETRSA_RSP_ERROR") == 0){
					puts(rxbuf);
				} 
				else{
					sqlite3_stmt* stmt;
					binn* obj;
					obj = binn_open(base64decode(rxbuf,strlen(rxbuf)));
					char* rsapub64 = binn_object_str(obj,"b64rsa");
					int rsalen = binn_object_int32(obj,"rsalen");
					sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen)values(NULL,?1,?2,?3);",-1,&stmt,NULL);
					sqlite3_bind_text(stmt,1,inbuf,-1,0);
					sqlite3_bind_text(stmt,2,(const char*)rsapub64,-1,0);
					sqlite3_bind_int(stmt,3,rsalen);
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);
					binn_free(obj);
				}
				break;

			case '3': //If User wants to receive messages do:
				puts("Getting Messages from Server...");
				char* buf = (char*)ServerGetMessages(db);
				BIO_write(tls_vars->bio_obj,buf,strlen(buf));
				free(buf);
				buf = NULL;
				char *recvbuf2 = malloc(20000);
				BIO_read(tls_vars->bio_obj,recvbuf2,20000);
				binn *list;
				list = binn_open(base64decode(recvbuf2,strlen(recvbuf2)));
				#ifdef SSC_VERIFY_VARIABLES
				if(list == NULL){
					puts("No new messages.");
					break;
				}
				#endif
				int lc = binn_count(list);
				int i;
				for(i=1;i<=lc;i++){
					binn *obj2 = binn_open(base64decode(binn_list_str(list,i),strlen(binn_list_str(list,i))));
					#ifdef SSC_VERIFY_VARIABLES
					assert(obj2 != NULL);
					#endif
					char* sender = binn_object_str(obj2,"sender");	
					decbuf = (char*)decryptmsg(binn_list_str(list,i),priv_evp); // decrypt
					if(decbuf == NULL) goto CLEANUP;		
					printf("Decrypted Message from %s: %s\n",sender,decbuf); 
					binn_free(obj2);
					obj2 = NULL;
				}
				binn_free(list);
				list = NULL;
				break;
		default: //Do nothing
				break;
		};
		
	}
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


const char* encryptmsg(char* username,unsigned char* message,sqlite3* db){ //returns b64 of binnobj that includes b64encryptedaeskey,aeskeylength,b64encrypedbuffer,encbuflen,b64iv,ivlen
	if(strlen((const char*)message) > 1024){
		puts("Message too long(limit 1024)");
		return NULL;	
	}
	binn* obj;
	obj = binn_object();	
	EVP_PKEY * userpubk = get_pubk_username(username,db);
	if(userpubk == NULL){
		puts("Could not get Users Public Key, maybe not in DB?");
		binn_free(obj);
		return NULL;
	}
	sqlite3_stmt *stmt;
        binn_object_set_str(obj,"recipient",username);
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
	binn_object_set_int32(obj,"msgp",MSGSND);
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
	#ifdef SSC_VERIFY_VARIABLES
	assert(final_b64 != NULL);
	#endif
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
	#ifdef SSC_VERIFY_VARIABLES
	assert((dec_len-1) <= 2000);
	#endif
	memcpy(f_buf,dec_buf,dec_len-1);
	binn_free(obj);
	free(dec_buf);
	return (const char*)f_buf;
}

