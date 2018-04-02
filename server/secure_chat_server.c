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
#include <assert.h>
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
#include "headers/settings.h" //settings for ssc

int sock = 0; //Global listen variable so it can be closed from a signal handler

int main(void){
    #ifdef SSC_VERIFY_VARIABLES
    puts("SSC_VERIFY_VARIABLES IS DEFINED.");
    #endif
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
 	SSL *ssl = NULL;
	ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
	
        BIO *accept_bio = BIO_new_socket(client, BIO_CLOSE);
        SSL_set_bio(ssl, accept_bio, accept_bio);
        
        SSL_accept(ssl);
        
        ERR_print_errors_fp(stderr);
        
        BIO *bio = BIO_pop(accept_bio);
	#ifdef SSC_VERIFY_VARIABLES
	assert(ssl != NULL);
	#endif
	char* buf = malloc(4096); //Main receive buffer for receiving from SSL socket
	char* sbinnobj = NULL;
	while(1){ //Handle request until interrupt or connection problems	
		memset(buf,'\0',4096);
        	int r = SSL_read(ssl,buf, 4095); 
		buf[4095] = '\0';
            	switch (SSL_get_error(ssl, r)){ 
	            	case SSL_ERROR_NONE: 
        	       		 break;
            		case SSL_ERROR_ZERO_RETURN: 
               		 	goto end; 
            		default: 
                		goto end;
            	}

		sbinnobj = base64decode(buf,strlen(buf));
		#ifdef SSC_VERIFY_VARIABLES
		assert(sbinnobj != NULL);
		#endif
		binn* obj0 = binn_open(sbinnobj);
		if(obj0 == NULL) goto end;

		int msgp0 = binn_object_int32(obj0,"msgp");
		if(msgp0 == REGRSA){ //User wants to register a username with a public key
			char* rusername = binn_object_str(obj0,"rusername");
			char* newline = strchr(rusername,'\n');
			if( newline ) *newline = 0;
	
			if(checkforUser(rusername,db) == 1){
				puts("Cannot add user: username already taken.");
			}
			else{
				puts("inserting user into db");
				char* b64rsa = binn_object_str(obj0,"b64rsa");
				int rsalen = binn_object_int32(obj0,"rsalen");
				char* authkey = binn_object_str(obj0,"authkey");
				if(strlen(authkey) != 256) goto end;
				if(addUser2DB(rusername,b64rsa,rsalen,authkey,db) != 1){
					puts("error inserting user");
				}
			}
		}
		else if(msgp0 == AUTHUSR){ //User wants to authenticate so he can receive messages.
			puts("User wants to authenticate, handling...");
			char* userauthk = (char*)binn_object_str(obj0,"authkey");
			if(strlen(userauthk) != 256) goto end; //If supplied authkey is not 256B exit
			char* authusername = (char*)binn_object_str(obj0,"username");
			char* userauthk_db = getUserAuthKey(authusername,db);
			if(memcmp(userauthk_db,userauthk,256) == 0){ //Compare stored authkey to usersupplied authkey
				printf("User %s authenticated.\n",authusername);
				binn_free(obj0);
				free(userauthk_db);
				userauthk_db = NULL; //for sanities sake set to NULL
				while(1){
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
					sbinnobj = base64decode(buf,strlen(buf));
					binn* obj = binn_open(sbinnobj);
					#ifdef SSC_VERIFY_VARIABLES
					if(obj == NULL) goto end;
					#endif
					int msgp = binn_object_int32(obj,"msgp");
					/*
					* Important Functions are only accessible when user has authenticated.
					*/
					if(msgp == GETRSA){ //Client is requesting a User Public Key
						puts("Client Requested Public Key,handling...");
						char* rsausername = binn_object_str(obj,"username");
						const char* uRSAenc = GetEncodedRSA(rsausername,db);
						if(uRSAenc != NULL) SSL_write(ssl,uRSAenc,strlen(uRSAenc));
					}
					else if(msgp == MSGREC){ //Client is requesting stored messages
						puts("Client Requesting New Messages,handling...");
						char* retmsg = GetUserMessagesSRV(authusername,db);
						printf("Length of message is %d\n",(int)strlen(retmsg));
						if(retmsg != NULL) SSL_write(ssl,retmsg,strlen(retmsg));
						//call function that returns an int,(messages available)send it to the client,and then send i messages to client in while() loop. 
					}
					else if(msgp == MSGSND){ //User wants to send a message to a user
						char* recipient = NULL;
						recipient = binn_object_str(obj,"recipient");
						char* sender = NULL;
						sender = binn_object_str(obj,"sender");
						if(strcmp(sender,authusername) != 0){
							puts("User tried to send a message with a fake username!");
							goto end;
						}	
						char* newline = strchr(recipient,'\n');
						if( newline ) *newline = 0;
						char* b64modbuf = base64encode(binn_ptr(obj),binn_size(obj));	
						#ifdef SSC_VERIFY_VARIABLES
						if(recipient == NULL)goto end;
						#endif
						printf("Buffering message from %s to %s\n",authusername,recipient);
						if(AddMSG2DB(db,recipient,(unsigned char*)b64modbuf) == -1){
							puts("Error Adding MSG to DB");
						}				
					}

					binn_free(obj);
					free(sbinnobj);
					sbinnobj = NULL; //for sanity reasons set to NULL
				}
			}
			else{
				printf("User %s failed to authenticate.\n",authusername);
				free(userauthk_db);
				userauthk_db = NULL; //for sanities sake
			}	
		}

		binn_free(obj0);
		obj0 = NULL;
		free(sbinnobj);
		sbinnobj = NULL; //for sanity reasons set to NULL
	}
end: //cleanup & exit
	puts("Ending Client Session");
	BIO_free(bio);
        SSL_free(ssl);
        close(client); 
	free(buf); 
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

