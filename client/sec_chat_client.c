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

#include "headers/binn.h" //Binn library 
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
#define KEYSIZE 2048 //keysize used to generate key (has to be 1024,2048,4096,or 8192)
#define DB_FNAME "sscdb.db" //SQLITE Database Filename

//Message Purposes
#define MSGSND 1 //Message Send(normal message)
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key from server
#define MSGREC 4 //Get new messages
//Server responses to the above.
#define MSGSND_RSP 5  
#define MSGREC_RSP 6
#define REGRSA_RSP 7
#define GETRSA_RSP 8
//Prototype functions
const char* encryptmsg(char* username,unsigned char* message,sqlite3* db); //encrypt buffer message with a public key fetched (index username) from the sqlite3 db (returns encryped buffer)

const char* decryptmsg(const char *encrypted_buffer,EVP_PKEY* privKey); // Attempts to decrypt buffer with your private key

const char* registerUserStr(char* username,sqlite3* db); //returns string you can pass to server to register your user with your public key.

const char* ServerGetUserRSA(char* username);

int addUser2DB_binn(char* recvbuf,char* username,sqlite3* db); //add user+pubkey combo from base64binn object

const char* ServerGetMessages(sqlite3* db); //Returns string that the server will interpret to send you your messages.
	
char* getMUSER(sqlite3* db); //Returns Username that has the uid=1 (your username)

int main(void){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/simplesecurechat/server')");
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars,HOST_CERT,HOST_NAME,HOST_PORT)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		//BIO_write(tls_vars->bio_obj,"12345 this is a more complicated message",40);
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
	char* yourusername = getMUSER(db);
	printf("Your username is: %s, trying to register it with the server\n",yourusername);
	char* regubuf = (char*)registerUserStr(yourusername,db);
	if(regubuf != NULL)BIO_write(tls_vars->bio_obj,regubuf,strlen(regubuf)); 

	char msg2test[1024];
	char* decbuf;
	char* encbuf;
//
//
// This is a very Quickly written approch to UI.
// There is ALOT of room for improvement.
//
	while(1){ //to be replaced by GUI
		puts("Options:Send message(1),AddUser(2),Get your messages(3)");
		int  options;
		options = fgetc(stdin);
		while(fgetc(stdin) != '\n'){}
		switch(options){
			case '1': //If User wants to send a message do:
				memset(msg2test,0,sizeof(msg2test));
				printf("recipient name: ");
				char runm[1024];
				fgets(runm,1024,stdin);
				puts("Message to user:");
				fgets(msg2test,1024,stdin);
				//sending user
				encbuf = (char*)encryptmsg(runm,(unsigned char*)msg2test,db); //"user" would be the receiving username
				printf("Encrypted message: %s with length: %d\n",encbuf,(int)strlen(encbuf));
				BIO_write(tls_vars->bio_obj,encbuf,strlen(encbuf));
				break;

			case '2': //If User wants to add another user do:
				memset(msg2test,0,sizeof(msg2test));
				puts("Username for public key to get:");
				fgets(msg2test,1024,stdin);
			
				const char* gtrsa64 = ServerGetUserRSA(msg2test);		
				puts(gtrsa64);
				BIO_write(tls_vars->bio_obj,gtrsa64,strlen(gtrsa64));
				char recvbuf[4096];
				memset(recvbuf,'\0',4096);
				BIO_read(tls_vars->bio_obj,recvbuf,4096);
				if(strcmp(recvbuf,"GETRSA_RSP_ERROR") == 0){
					puts(recvbuf);
				} 
				else{
					sqlite3_stmt* stmt;
					binn* obj;
					obj = binn_open(base64decode(recvbuf,strlen(recvbuf)));
					char* rsapub64 = binn_object_str(obj,"b64rsa");
					int rsalen = binn_object_int32(obj,"rsalen");
					sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen)values(NULL,?1,?2,?3);",-1,&stmt,NULL);
					sqlite3_bind_text(stmt,1,msg2test,-1,0);
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
				char recvbuf2[200000];
				BIO_read(tls_vars->bio_obj,recvbuf2,200000);
				binn *list;
				list = binn_open(base64decode(recvbuf2,strlen(recvbuf2)));
				int lc = binn_count(list);
				int i;
				for(i=1;i<=lc;i++){
					binn *obj2 = binn_open(base64decode(binn_list_str(list,i),strlen(binn_list_str(list,i))));
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
		default: //Do nothing..
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
	
const char* registerUserStr(char* username,sqlite3* db){ //returns string you can pass to server to register your user with your public key.
	char username2[1024];
	sprintf(username2,"%s",username); //Stupid Way to add a '\0'(Null termination) to the username
	int uid = getUserUID(username2,db); //get UID for username
	sqlite3_stmt *stmt;
	int rsalen;
	unsigned char *b64buf = NULL;
	sqlite3_prepare_v2(db,"select rsapub64,rsalen from knownusers where uid=?1",-1,&stmt,NULL);
	sqlite3_bind_int(stmt,1,uid);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		rsalen = sqlite3_column_int(stmt,1);
		b64buf = (unsigned char*)sqlite3_column_text(stmt,0);
	}
	else{
		puts("Cannot get userpubkey for registering user.");
		sqlite3_finalize(stmt);
		return NULL;
	}
	sqlite3_finalize(stmt);	
	binn* obj;
	obj = binn_object();
	binn_object_set_int32(obj,"msgp",REGRSA); //message purpose
	binn_object_set_str(obj,"b64rsa",(char*)b64buf); //set rsakey
	binn_object_set_int32(obj,"rsalen",rsalen);
	binn_object_set_str(obj,"rusername",(char*)getMUSER(db));
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	return final_b64;
}

const char* ServerGetUserRSA(char* username){ //Generates a character array that can be sent the message buffer server to request a userpublickey
	binn* obj;
	obj = binn_object();
	char* newline = strchr(username,'\n');
	if(newline)*newline=0;
	binn_object_set_int32(obj,"msgp",GETRSA);
	binn_object_set_str(obj,"username",username);
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	return final_b64;		
}

int addUser2DB_binn(char* recvbuf,char* username,sqlite3* db){ //adds user+pubkey to knownusers database (needs to be done before sending a message)
	sqlite3_stmt* stmt;
	binn* obj;
	obj = binn_open(base64decode(recvbuf,strlen(recvbuf)));
	char* rsapub64 = binn_object_str(obj,"b64rsa");
	int rsalen = binn_object_int32(obj,"rsalen");
	sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen)values(NULL,?1,?2,?3);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,username,-1,0);
	sqlite3_bind_text(stmt,2,(const char*)rsapub64,-1,0);
	sqlite3_bind_int(stmt,3,rsalen);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	binn_free(obj);
	return 0;
}
const char* ServerGetMessages(sqlite3* db){ //Generates a character array that can be sent to message buffer server to receive back your stored encrypted message
	char* username = getMUSER(db);
	binn* obj;
	obj = binn_object();
	binn_object_set_int32(obj,"msgp",MSGREC);
	binn_object_set_str(obj,"username",username);
	//binn_object_set_str(obj,"authkey",authkey); //will in the future be used(registered with the name), sha256 and stored in server db.
	const char* msg2srv64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	return msg2srv64;
}
char* getMUSER(sqlite3* db){ // Returns the main Username (user with the uid of 1)
	sqlite3_stmt* stmt;
	sqlite3_prepare(db,"select username from knownusers where uid=1",-1,&stmt,NULL);
	char* muser = NULL;
	if(sqlite3_step(stmt) == SQLITE_ROW){ 
		 muser = (char*)sqlite3_column_text(stmt,0);
	}
	sqlite3_finalize(stmt);
	return muser;
}
