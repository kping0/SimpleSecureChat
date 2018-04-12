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
#include "sscdbfunc.h"
#include "binn.h"
#include "serialization.h"
#include "base64.h"

sqlite3* initDB(char* dbfname){
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc = sqlite3_open(dbfname,&db);
	if(rc){ 
		return NULL;
	}
	char* sql = "CREATE TABLE MESSAGES(MSGID INTEGER PRIMARY KEY,UID INT NOT NULL,UID2 INT NOT NULL,MESSAGE TEXT NOT NULL);"; //table where msgid(msgid),uid is sender(can be you),uid2 is recipient (can be you)
	sqlite3_exec(db,sql,NULL,0,NULL);

	sql = "CREATE TABLE KNOWNUSERS(UID INTEGER PRIMARY KEY,USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL,RSALEN INTEGER NOT NULL,AUTHKEY TEXT);"; //list of known users and public keys associated with the users
	sqlite3_exec(db,sql,NULL,0,NULL);
	
	sql = "CREATE TABLE SETTINGS(SID INTEGER PRIMARY KEY,SNAME TEXT NOT NULL,SVAL INTEGER NOT NULL);";
	sqlite3_exec(db,sql,NULL,0,NULL);

	sql = "insert into messages(msgid,uid,uid2,message)values(0,0,0,'testmessage');";
	sqlite3_exec(db,sql,NULL,0,NULL);
	
	sql = "insert into knownusers(uid,username,rsapub64,rsalen) values(0,'testuser','testuser',0);";
	sqlite3_exec(db,sql,NULL,0,NULL);
	
	sql = NULL;
	sqlite3_prepare_v2(db,"select * from messages where msgid=0",-1,&stmt,NULL);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		puts("Loaded SQLITE OK");
	}else{
		puts("Loaded SQLITE ERROR");
		return NULL;			
	}
	sqlite3_finalize(stmt);	
	stmt = NULL;
	return db;
}

void addKnownUser(char* username,RSA *userpubkey,sqlite3 *db,char* authkey){ // adds user to DB
	unsigned char *buf,*b64buf;
	int len;
	sqlite3_stmt *stmt;
	buf = NULL;
	b64buf = NULL;
	
	len = i2d_RSAPublicKey(userpubkey, &buf);
	if (len < 0) return;
	b64buf = (unsigned char*)base64encode(buf,len);
	sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen,authkey)values(NULL,?1,?2,?3,?4);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,username,-1,0);
	sqlite3_bind_text(stmt,2,(const char*)b64buf,-1,0);
	sqlite3_bind_int(stmt,3,len);
	if(authkey != NULL)sqlite3_bind_text(stmt,4,(const char*)authkey,-1,0);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;
	return;
}

int getUserUID(char* username,sqlite3 *db){ //gets uid from user (to add a message to db for ex.)
	int uid = -1; //default is error	
	char *newline = strchr(username,'\n');
	if ( newline ) *newline = 0;
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"select uid from knownusers where username = ?1",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,username,-1,0);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		uid = sqlite3_column_int(stmt,0);
	}
	sqlite3_finalize(stmt);
	stmt = NULL;
	return uid;
}
int DBUserInit(sqlite3 *db,char* pkeyfn){ //check for own user & create if not found
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"select username from knownusers where uid=1",-1,&stmt,NULL); //check for own user.
	if(sqlite3_step(stmt) == SQLITE_ROW){
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	else{
		sqlite3_finalize(stmt);	
		stmt = NULL;	
		//get user input for username	
		printf("What do you want your username to be?(200):");
		char username[200];
		fgets(username,200,stdin);
		char *newline = strchr(username,'\n');
		if ( newline ) *newline = 0;
		printf("Are you sure ?\"%s\"(Y/N): ",username);
		int choice = fgetc(stdin);
		switch(choice){
			case 'Y':
				break;
			case 'y':
				break;
			default:
				puts("exiting...");
				return 0;
		}
		//create entry in DB if run for the first time
		BIO* rsa_pub_bio = BIO_new_file(pkeyfn,"r");
		if(rsa_pub_bio == NULL){
			puts("error loading public key!"); //error checking
			return 0;	
		}
		RSA* rsa_pubk = RSA_new();
		PEM_read_bio_RSAPublicKey(rsa_pub_bio,&rsa_pubk,NULL,NULL);
		unsigned char* authkey = malloc(512);
		RAND_poll();
		if(RAND_bytes(authkey,512) != 1){
			puts("Generating authkey ERROR");
			return 0;
		}
		char* b64authkey = base64encode(authkey,512);
		char* b64authkey256 = malloc(256);
		memcpy(b64authkey256,b64authkey,256); //Shorten take part of b64encoded random value as 256 Byte authkey
		b64authkey256[256] = '\0';
		(void)addKnownUser(username,rsa_pubk,db,b64authkey256);
		free(authkey);
		free(b64authkey);
		free(b64authkey256);
	}
	return 1;
}

EVP_PKEY *get_pubk_uid(int uid,sqlite3 *db){ //Get public key based on UID
	EVP_PKEY *pubkey = EVP_PKEY_new();
	sqlite3_stmt *stmt;
	RSA* x = NULL;
	unsigned char* buf,*b64buf,*p;
	sqlite3_prepare_v2(db,"select rsapub64,rsalen from knownusers where uid=?1",-1,&stmt,NULL);
	sqlite3_bind_int(stmt,1,uid);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		int rsalen = sqlite3_column_int(stmt,1);
		b64buf = (unsigned char*)sqlite3_column_text(stmt,0);
		buf = (unsigned char*)base64decode(b64buf,strlen((const char*)b64buf));
		p = buf;
		if(!d2i_RSAPublicKey(&x,(const unsigned char**)&p, rsalen)) return NULL;
		EVP_PKEY_assign_RSA(pubkey,x);
	}	
	sqlite3_finalize(stmt);
	stmt = NULL;
	return pubkey;
}

EVP_PKEY *get_pubk_username(char* username,sqlite3 *db){ // Get public key based on Username
	int uid = getUserUID(username,db); //get UID for username
	EVP_PKEY *pubkey = EVP_PKEY_new();
	sqlite3_stmt *stmt;
	RSA* x = NULL;
	unsigned char *buf,*b64buf,*p;
	sqlite3_prepare_v2(db,"select rsapub64,rsalen from knownusers where uid=?1",-1,&stmt,NULL);
	sqlite3_bind_int(stmt,1,uid);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		int rsalen = sqlite3_column_int(stmt,1);
		b64buf = (unsigned char*)sqlite3_column_text(stmt,0);
		buf = (unsigned char*)base64decode(b64buf,strlen((const char*)b64buf));
		p = buf;
		if(!d2i_RSAPublicKey(&x,(const unsigned char**)&p, rsalen)) return NULL;
		EVP_PKEY_assign_RSA(pubkey,x);
	}
	else{
		sqlite3_finalize(stmt);
		return NULL;
	}
	sqlite3_finalize(stmt);
	stmt = NULL;
	return pubkey;

}
const char* registerUserStr(sqlite3* db){ //returns string you can pass to server to register your user with your public key.

	sqlite3_stmt *stmt;
	int rsalen;
	unsigned char *b64buf = NULL;
	unsigned char* authkey = NULL;
	sqlite3_prepare_v2(db,"select rsapub64,rsalen,authkey from knownusers where uid=1",-1,&stmt,NULL);
	if(sqlite3_step(stmt) == SQLITE_ROW){ //Get B64 Public Key for local user
		rsalen = sqlite3_column_int(stmt,1);
		b64buf = (unsigned char*)sqlite3_column_text(stmt,0);
		authkey = (unsigned char*)sqlite3_column_text(stmt,2); //get authkey 
	}
	else{
		puts("Cannot get userpubkey for registering user.");
		sqlite3_finalize(stmt);
		return NULL;
	}
	binn* obj;
	obj = binn_object();
	binn_object_set_int32(obj,"msgp",REGRSA); //message purpose
	binn_object_set_str(obj,"b64rsa",(char*)b64buf); //set B64 Public Key of local user
	binn_object_set_int32(obj,"rsalen",rsalen); //length of rsakey(needed for deserializing)
	binn_object_set_str(obj,"rusername",(char*)getMUSER(db)); //Username to register 
	binn_object_set_str(obj,"authkey",(char*)authkey); //authkey
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj)); //Encode Everything
	binn_free(obj);
	sqlite3_finalize(stmt);	
	return final_b64;
}

const char* ServerGetUserRSA(char* username){ //Generates a character array that can be sent the message buffer server to request a userpublickey
	binn* obj;
	obj = binn_object();
	char* newline = strchr(username,'\n');
	if(newline)*newline=0;
	binn_object_set_int32(obj,"msgp",GETRSA); //message purpose
	binn_object_set_str(obj,"username",username); //Set to user requested
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj)); //Encode Everything
	binn_free(obj);
	return final_b64;		
}

const char* ServerGetMessages(sqlite3* db){ //Generates a character array that can be sent to message buffer server to receive back your stored encrypted message
	char* username = getMUSER(db);
	binn* obj;
	obj = binn_object();
	binn_object_set_int32(obj,"msgp",MSGREC); //message purpose
	binn_object_set_str(obj,"username",username); //Current username
	//binn_object_set_str(obj,"authkey",authkey); //will in the future be used(registered with the name), sha256 and stored in server db.
	const char* msg2srv64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	return msg2srv64;
}

char* getMUSER(sqlite3* db){ // Returns the main Username (user with the uid of 1)
	sqlite3_stmt* stmt;
	sqlite3_prepare(db,"select username from knownusers where uid=1",-1,&stmt,NULL);
	char* muser = malloc(200);
	if(sqlite3_step(stmt) == SQLITE_ROW){ 
		 sprintf(muser,"%s",sqlite3_column_text(stmt,0));	
	     	 sqlite3_finalize(stmt);
	}
	else{
		sqlite3_finalize(stmt);
		return NULL;
	}
	return muser;
}

char* AuthUSR(sqlite3* db){
	sqlite3_stmt* stmt;
	char* authkey = NULL;
	sqlite3_prepare_v2(db,"select authkey from knownusers where uid=1;",-1,&stmt,NULL);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		authkey = (char*)sqlite3_column_text(stmt,0);
//		printf("Your authkey is:%s\n",authkey);
	}
	else{
		sqlite3_finalize(stmt);
		return NULL;
	}
	binn* obj = binn_object();
	char* username = getMUSER(db);
	binn_object_set_str(obj,"username",username);
	binn_object_set_int32(obj,"msgp",AUTHUSR);
	binn_object_set_str(obj,"authkey",authkey);
	char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	sqlite3_finalize(stmt);
	return final_b64;
}

