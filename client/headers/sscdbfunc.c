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

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

/* https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

sqlite3* initDB(char* dbfname){
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc = sqlite3_open(dbfname,&db);
	char *errm = 0;
	if(rc){ 
		sqlite3_free(errm);
		return NULL;
	}
	char* sql = "CREATE TABLE MESSAGES(MSGID INTEGER PRIMARY KEY,UID INT NOT NULL,UID2 INT NOT NULL,MESSAGE TEXT NOT NULL);"; //table where msgid(msgid),uid is sender(can be you),uid2 is recipient (can be you)
	sqlite3_exec(db,sql,NULL,0,&errm);

	sql = "CREATE TABLE KNOWNUSERS(UID INTEGER PRIMARY KEY,USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL,RSALEN INTEGER NOT NULL);"; //list of known users and public keys associated with the users
	sqlite3_exec(db,sql,NULL,0,&errm);

	sql = "insert into messages(msgid,uid,uid2,message)values(0,0,0,'testmessage');";
	sqlite3_exec(db,sql,NULL,0,&errm);
	
	sql = "insert into knownusers(uid,username,rsapub64,rsalen) values(0,'testuser','testuser',0);";
	sqlite3_exec(db,sql,NULL,0,&errm);
	
	sqlite3_free(errm);
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

void addKnownUser(char* username,RSA *userpubkey,sqlite3 *db){ // adds user to DB
	unsigned char *buf,*b64buf;
	int len;
	sqlite3_stmt *stmt;
	buf = NULL;
	b64buf = NULL;
	
	len = i2d_RSAPublicKey(userpubkey, &buf);
	if (len < 0) return;
	b64buf = (unsigned char*)base64encode(buf,len);
	sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen)values(NULL,?1,?2,?3);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,username,-1,0);
	sqlite3_bind_text(stmt,2,(const char*)b64buf,-1,0);
	sqlite3_bind_int(stmt,3,len);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;
	return;
}

int getUserUID(char* username,sqlite3 *db){ //gets uid from user (to add a message to db for ex.)
	int uid = -1; //default is error	
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
		(void)addKnownUser(username,rsa_pubk,db);
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
	sqlite3_finalize(stmt);
	stmt = NULL;
	return pubkey;

}

