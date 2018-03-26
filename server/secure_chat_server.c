#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
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

#define SRVDB "srvdb.db" //Server message database filename.

//Message Purposes
#define MSGSND 1 //Message Send(normal message)
#define MSGREC 4 //Get new messages 
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key

#define MSGSND_RSP 5 //Server response to MSGSND
#define MSGREC_RSP 6 //Server response to MSGREC
#define REGRSA_RSP 7 //Server response to REGRSA
#define GETRSA_RSP 8 //Server response to GETRSA
int sock = 0; //Bad workaround but basically so that if a signal is received the socket can be closed

volatile int gsigflag = 0; //flag so that SIGINT is not handled twice if CTRL-C is hit twice

int checkforUser(char* username,sqlite3* db); 

int addUser2DB(char* username,char* b64rsa,int rsalen,sqlite3* db);
	
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

void sig_handler(int sig);

void childexit_handler(int sig);

int getUserUID(char* username,sqlite3 *db);

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message);

sqlite3* initDB(char* dbfname);

const char* GetEncodedRSA(char* username, sqlite3* db);

char* GetUserMessagesSRV(char* username,sqlite3* db);

int main(void){
    //register signal handlers..
    signal(SIGINT,sig_handler);
    signal(SIGABRT,sig_handler);
    signal(SIGFPE,sig_handler);
    signal(SIGILL,sig_handler);
    signal(SIGSEGV,sig_handler);
    signal(SIGTERM,sig_handler);
    signal(SIGCHLD,childexit_handler);
    //initialize the sqlite3 database
    sqlite3* db = initDB(SRVDB); 
	
    SSL_CTX *ctx;

    //initalize openssl and create the ssl_ctx context
    init_openssl();
    ctx = create_context();

    configure_context(ctx);
    //Setup listening socket
    sock = create_socket(5050);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
	
	// Accept Client Connections.
        int client = accept(sock, (struct sockaddr*)&addr, &len);
	printf("Connection from: %s:%i\n",inet_ntoa(addr.sin_addr),(int)ntohs(addr.sin_port));
	/*
	* We fork(clone the process) to handle each client. On exit these zombies are handled
	* by the function childexit_handler
	*/
	pid_t pid = fork();
	if(pid == 0){ //If the pid is 0 we are running in the child process(our designated handler) 
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
	//Setup ssl with the client.
 	SSL *ssl;
	ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
	
        BIO *accept_bio = BIO_new_socket(client, BIO_CLOSE);
        SSL_set_bio(ssl, accept_bio, accept_bio);
        
        SSL_accept(ssl);
        
        ERR_print_errors_fp(stderr);
        
        BIO *bio = BIO_pop(accept_bio);
	while(1){ //Handle request until interrupt or connection problems	
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
		binn* obj = binn_open(base64decode(buf,strlen(buf)));
		if(obj == NULL) goto end;
		int msgp = binn_object_int32(obj,"msgp");
		if(msgp == MSGSND){ //User wants to send a message to a user
			char* recipient = NULL;
			recipient = binn_object_str(obj,"recipient");
			char* newline = strchr(recipient,'\n');
			if( newline ) *newline = 0;
	
			if(recipient == NULL)goto end;
			printf("Buffering message from %s to %s\n",binn_object_str(obj,"sender"),recipient);
			if(AddMSG2DB(db,recipient,(unsigned char*)buf) == -1){
				puts("Error Adding MSG to DB");
			}
		}
		else if(msgp == REGRSA){ //User wants to register a username with a public key
			char* rusername = binn_object_str(obj,"rusername");
			char* newline = strchr(rusername,'\n');
			if( newline ) *newline = 0;
	
			if(checkforUser(rusername,db) == 1){
				SSL_write(ssl,"REGRSA_RSP_ERROR",16);
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
		else if(msgp == GETRSA){ //Client is requesting a User Public Key
			puts("Client Requested Public Key,handling...");
			char* rsausername = binn_object_str(obj,"username");
			const char* uRSAenc = GetEncodedRSA(rsausername,db);
			if(uRSAenc != NULL) SSL_write(ssl,uRSAenc,strlen(uRSAenc));
		}
		else if(msgp == MSGREC){ //Client is requesting stored messages
			puts("Client Requesting New Messages,handling...");
			char* username = binn_object_str(obj,"username");
			char* retmsg = GetUserMessagesSRV(username,db);
			printf("Length of message is %d\n",(int)strlen(retmsg));
			if(retmsg != NULL) SSL_write(ssl,retmsg,strlen(retmsg));
			//call function that returns an int,(messages available)send it to the client,and then send i messages to client in while() loop. 
		}

		sleep(1);
		binn_free(obj);
	}
end: //Commands to run before exit & then exit
	puts("Ending Client Session");
	BIO_free(bio);
        SSL_free(ssl);
        close(client);
	exit(0);
	} 
	/*
	* End of Client Handler Code
	*/


    } 
    //If while loop is broken close listening socket and do cleanup
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
int checkforUser(char* username,sqlite3* db){ //Check if user exists in database, returns 1 if true, 0 if false
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
int addUser2DB(char* username,char* b64rsa,int rsalen,sqlite3* db){ //Add User to database, returns 1 on success,0 on error
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


void sig_handler(int sig){ //Function to handle signals
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
		}
	}
}

int getUserUID(char* username,sqlite3 *db){ //gets uid for the username it is passed in args (to add a message to db for ex.)
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

int AddMSG2DB(sqlite3* db,char* recipient,unsigned char* message){ //Adds a message to the database, returns 1 on success, 0 on error
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"insert into messages(msgid,recvuid,message)values(NULL,?1,?2);",-1,&stmt,NULL);
	int recvuid = getUserUID(recipient,db);
	if(recvuid == -1){
		puts("UID for recipient not found.");
		return 0;
	}
	sqlite3_bind_int(stmt,1,recvuid);
	sqlite3_bind_text(stmt,2,(const char*)message,-1,0);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;
	return 1;
}

sqlite3* initDB(char* dbfname){ //Initalize the Mysql Database and create the tables if not existant
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


const char* GetEncodedRSA(char* username, sqlite3* db){ //Functions that returns an encoded user RSA key.
	binn* obj;
	obj = binn_object();
	char* newline = strchr(username,'\n');
	if( newline ) *newline = 0;
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(db,"SELECT RSAPUB64,RSALEN FROM KNOWNUSERS WHERE USERNAME=?1;",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,username,-1,0);
	if(sqlite3_step(stmt) != SQLITE_ROW){
		sqlite3_finalize(stmt);
		return "GETRSA_RSP_ERROR";
	}
	char* rsapub64 = (char*)sqlite3_column_text(stmt,0);
	int rsalen = sqlite3_column_int(stmt,1);
	binn_object_set_int32(obj,"msgp",GETRSA_RSP);
	binn_object_set_str(obj,"b64rsa",rsapub64);
	binn_object_set_int32(obj,"rsalen",rsalen);
	sqlite3_finalize(stmt);
	const char* final_b64 = base64encode(binn_ptr(obj),binn_size(obj));
	binn_free(obj);
	return final_b64;
}


char* GetUserMessagesSRV(char* username,sqlite3* db){ //Returns buffer with encoded user messages
	sqlite3_stmt* stmt;
	binn* list;
	list = binn_list();
	sqlite3_prepare_v2(db,"select message from messages where recvuid=?1;",-1,&stmt,NULL);
	int uid = getUserUID(username,db);
	sqlite3_bind_int(stmt,1,uid);
	while(sqlite3_step(stmt) == SQLITE_ROW){
		binn_list_add_str(list,(char*)sqlite3_column_text(stmt,0));
	}
	sqlite3_finalize(stmt);
	char* usermsgbuf64 = base64encode(binn_ptr(list),binn_size(list));
	binn_free(list);
	return usermsgbuf64;
}


void childexit_handler(int sig){ //Is registered to the Signal SIGCHLD, kills all zombie processes
	int saved_errno = errno;
	while(waitpid((pid_t)(-1),0,WNOHANG) > 0){}
	errno = saved_errno;
}

