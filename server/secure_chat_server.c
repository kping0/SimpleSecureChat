#include <string.h>
#include <signal.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <sqlite3.h>
#include "headers/binn.h" //Binn library 
#include "headers/sscsrvfunc.h" //Some SSL functions 

#define SRVDB "srvdb.db" //Server message database.

//Message Purposes
#define MSGSND 1 //Message Send(normal message)
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key from server
#define MSGREC 4 //Get new messages

int sock = 0;
int gsigflag = 0; //flag so that SIGINT is not handled twice if CTRL-C is hit twice

int checkforUser(char* username,sqlite3* db);

int addUser2DB(char* username,char* b64rsa,int rsalen,sqlite3* db);
	
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

void sig_handler(int sig);

int getUserUID(char* username,sqlite3 *db);

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message);

sqlite3* initDB(char* dbfname);

int main(void){
    signal(SIGINT,sig_handler);
    signal(SIGABRT,sig_handler);
    signal(SIGFPE,sig_handler);
    signal(SIGILL,sig_handler);
    signal(SIGSEGV,sig_handler);
    signal(SIGTERM,sig_handler);
    sqlite3* db = initDB(SRVDB); 
	
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(5050);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
     	
	
        int client = accept(sock, (struct sockaddr*)&addr, &len);
	printf("Connection from: %s:%i\n",inet_ntoa(addr.sin_addr),(int)ntohs(addr.sin_port));
	pid_t pid = fork();
	if(pid == 0){ //Start of forked(STARTOF Session Handler)
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
 	SSL *ssl;
	ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
	
        BIO *accept_bio = BIO_new_socket(client, BIO_CLOSE);
        SSL_set_bio(ssl, accept_bio, accept_bio);
        
        SSL_accept(ssl);
        
        ERR_print_errors_fp(stderr);
        
        BIO *bio = BIO_pop(accept_bio);
	while(1){	
		char buf[4096];
		memset(buf,'\0',4096);
        	int r = SSL_read(ssl,buf, 4096); 
            	switch (SSL_get_error(ssl, r))
            	{ 
            	case SSL_ERROR_NONE: 
               		 break;
            	case SSL_ERROR_ZERO_RETURN: 
                	goto end; 
            	default: 
                	goto end;
            	}
		buf[4095] = '\0';
		SSL_write(ssl,buf,4095);
		binn* obj = binn_open(base64decode(buf,strlen(buf)));
		if(obj == NULL) goto end;
		int msgp = binn_object_int32(obj,"msgp");
		if(msgp == MSGSND){
			char* recipient = NULL;
			recipient = binn_object_str(obj,"recipient");
			if(recipient == NULL)goto end;
			printf("Buffering message from %s to %s\n",binn_object_str(obj,"sender"),recipient);
			if(AddMSG2DB(db,recipient,(unsigned char*)buf) == -1){
				puts("Error Adding MSG to DB");
			}
		}
		else if(msgp == REGRSA){
			char* rusername = binn_object_str(obj,"rusername");
			if(checkforUser(rusername,db) == 1){
//				SSL_write(ssl,"USRTKN",6); //Send USRTKN if user is taken
				puts("Cannot add user: username already taken.");
			}
			else{
				puts("inserting user into db");
				char* b64rsa = binn_object_str(obj,"b64rsa");
				int rsalen = binn_object_int32(obj,"rsalen");
				if(addUser2DB(rusername,b64rsa,rsalen,db) != 1){
					puts("error inserting user");
				}
			}
		}

		sleep(1);
		binn_free(obj);
	}
end:
	puts("Ending Client Session");
	BIO_free(bio);
        SSL_free(ssl);
        close(client);
	exit(0);
	} //end of forked
    } //End of while loop (ENDOF Session Handler)

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
int checkforUser(char* username,sqlite3* db){
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"select uid from knownusers where username = ?1",-1,&stmt,0);
	sqlite3_bind_text(stmt,1,username,-1,0);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		sqlite3_finalize(stmt);
		return 1;	
	}
	else{
		sqlite3_finalize(stmt);
		return 0;
	}	
}
int addUser2DB(char* username,char* b64rsa,int rsalen,sqlite3* db){
	printf("Trying to add user: %s,b64rsa is %s, w len of %i\n",username,b64rsa,rsalen);
	sqlite3_stmt* stmt;
	char* sql = "insert into knownusers(uid,username,rsapub64,rsalen)  values(NULL,?1,?2,?3);";
	sqlite3_prepare_v2(db,sql,-1,&stmt,0);
	sqlite3_bind_text(stmt,1,username,-1,0);
	sqlite3_bind_text(stmt,2,b64rsa,-1,0);
	sqlite3_bind_int(stmt,3,rsalen);
	if(sqlite3_step(stmt) != SQLITE_DONE){
		puts("error in sql statement exec");
		return 0;
	}
	sqlite3_finalize(stmt);
	return 1;	

}
	
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


void sig_handler(int sig){
	if(gsigflag != 1){ //check if signal was sent once already
	gsigflag = 1;
	if(sig == SIGINT || sig == SIGABRT || sig == SIGTERM){
		printf("\nCaught Signal... Exiting\n");
		cleanup_openssl();
		if(sock != 0){
			close(sock);
			sock = 0;
		}	
		exit(EXIT_SUCCESS);
	}
	else if(sig == SIGFPE){
		exit(EXIT_FAILURE);	
	}
	else if(sig == SIGILL){
		exit(EXIT_FAILURE);
	}
	else{
		exit(EXIT_FAILURE);	
	}}
}

int getUserUID(char* username,sqlite3 *db){ //gets uid from user (to add a message to db for ex.)
        int uid = -1; //default is error        
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db,"select uid from knownusers where username=?1",-1,&stmt,NULL);
        sqlite3_bind_text(stmt,1,username,-1,0);
        if(sqlite3_step(stmt) == SQLITE_ROW){
                uid = sqlite3_column_int(stmt,0);
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        return uid;
}

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message){
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"insert into messages(msgid,recvuid,message)values(NULL,?1,?2);",-1,&stmt,NULL);
	int recvuid = getUserUID(recipient,db);
	if(recvuid == -1){
		puts("UID for recipient not found.");
		return -1;
	}
	sqlite3_bind_int(stmt,1,recvuid);
	sqlite3_bind_text(stmt,2,(const char*)message,-1,0);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;
	return 0;
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
	char* sql = "CREATE TABLE MESSAGES(MSGID INTEGER PRIMARY KEY,RECVUID INTEGER NOT NULL,MESSAGE TEXT NOT NULL);"; // table for messages 
	sqlite3_exec(db,sql,NULL,0,&errm);

	sql = "CREATE TABLE KNOWNUSERS(UID INTEGER PRIMARY KEY,USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL,RSALEN INTEGER NOT NULL);"; //list of known users and public keys associated with the users
	sqlite3_exec(db,sql,NULL,0,&errm);

	sql = "insert into messages(msgid,recvuid,message)values(0,0,'testmessage');";
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


