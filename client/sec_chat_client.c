/*
 *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
 *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include <openssl/sha.h>
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
#include "headers/sscssl.h" //Connection functions
#include "headers/sscasymmetric.h" //keypair functions
#include "headers/sscdbfunc.h" //DB manipulation functions 
#include "headers/base64.h" //Base64 Functions
#include "headers/serialization.h" //SimpleSecureSerialization library (to replace binn)
#include "headers/msgfunc.h" //encrypt-decrypt-verify-sign functions
//All configurable settings
#include "headers/settings.h" //Modify to change configuration of SSC

#ifdef SSC_GUI
#include <gtk/gtk.h>
#include "headers/gui.h"
#endif /* SSC_GUI */

#define UNUSED(x)((void)x)
typedef unsigned char byte; //Create type "byte" NOTE: only when the build system version of type "char" is 8bit

int pexit(char* error){
	printf("Exiting, error : %s\n",error);
	exit(1);
}
//Startpoint
int main(void){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://github.com/kping0/simplesecurechat/server')");
	#ifdef SSC_VERIFY_VARIABLES
	puts("SSC_VERIFY_VARIABLES IS DEFINED.");
	#endif
	#ifndef SSC_VERIFY_VARIABLES
	puts("SSC_VERIFY_VARIABLES IS NOT DEFINED");
	#endif
	#ifdef SSC_GUI
	puts("SSC_GUI IS DEFINED");
	#endif
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars,HOST_CERT,HOST_NAME,HOST_PORT)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		puts("SSL/TLS OK");
		puts("Connected to " HOST_NAME ":" HOST_PORT " using server-cert: " HOST_CERT);
	}
	else{
		puts("SSL/TLS ERROR");	
		puts("Exiting, cannot establish connection with server");
		free(tls_vars);
		exit(1);
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
#ifdef DEBUG
	puts("Starting Signing/Verifying Test");
	const byte msg[] = "This is a secret message";
	byte *sig = NULL;
	size_t slen = 0;
	int rc = signmsg(msg,sizeof(msg),&sig,&slen,priv_evp);
	if(rc == 0) {
       		 printf("Created signature\n");
    	} else {
       		 printf("Failed to create signature, return code %d\n", rc);
   	}
	rc = verifymsg(msg,sizeof(msg),sig,slen,pubk_evp);
	if(rc == 0){
		puts("Verified Signature");
	}	
	else{
		puts("failed to verify signature");
	}
#endif
	
//test
#ifdef DEBUG
	sscso* obj = SSCS_object();
	int testint = 45;
	SSCS_object_add_data(obj,"msgp",&testint,sizeof(int));
	BIO_write(tls_vars->bio_obj,SSCS_object_encoded(obj),SSCS_object_encoded_size(obj));
	BIO_write(tls_vars->bio_obj,SSCS_object_encoded(obj),SSCS_object_encoded_size(obj));
#endif
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
/* Up to here the GUI and the CLI are the same */

#ifdef SSC_GUI
	/*
	* Setting up gui variables & more 
	*/
	puts("Starting GUI...");
	struct sscs_backend_variables* backend_vars = malloc(sizeof(struct sscs_backend_variables));
	backend_vars->pubkey = pubk_evp;
	backend_vars->privkey = priv_evp;
	backend_vars->db = db;
	backend_vars->connection_variables = tls_vars;

	GtkWidget *window;
	gtk_init(NULL,NULL);
	GtkBuilder* gtkBuilder = gtk_builder_new();		
	gtkBuilder = gtk_builder_new();
	gtk_builder_add_from_file(gtkBuilder,"gui.glade",NULL);
	window = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"mainwindow"));
	GtkWidget *contactslist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"contactslist"));
	GtkWidget *messagelist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"messageslist"));
	GtkWidget *sendmessagetext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"sendmessagetext"));
	GtkWidget *addusertext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"addusertext"));
	GtkWidget *chatpartnerlabel = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"currentchatpartner"));
	GtkWidget *getmsg = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"getmsg"));
	GtkWidget *recvlist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"recvlist"));
	struct sscswidgets_gui* widgetsobj = malloc(sizeof(struct sscswidgets_gui));
	widgetsobj->window = window;
	widgetsobj->contactslist = contactslist;
	widgetsobj->messagelist = messagelist;
	widgetsobj->chatpartnerlabel = chatpartnerlabel;
	widgetsobj->recvlist = recvlist;
	widgetsobj->backend_vars = backend_vars;
	char* username = NULL;
	widgetsobj->current_username = &username;
	g_object_unref(G_OBJECT(gtkBuilder));
	//Connect signals 
	g_signal_connect(G_OBJECT(window),"destroy",G_CALLBACK(gtk_main_quit),NULL);
	g_signal_connect(G_OBJECT(sendmessagetext),"activate",G_CALLBACK(send_message_entry_gui),widgetsobj);
	g_signal_connect(G_OBJECT(addusertext),"activate",G_CALLBACK(add_user_entry_gui),widgetsobj);
	g_signal_connect(G_OBJECT(getmsg),"clicked",G_CALLBACK(getmessages_gui),widgetsobj);
	init_gui(widgetsobj); //Add known users to sidebar (this is NOT gtk_init)
	gtk_widget_show_all(window);
	gtk_main();
	goto CLEANUP;
#endif /* SSC_GUI */

#ifdef SSC_CLI
//
// This is a very Quickly written CLI version
//

	char* decbuf;
	char* encbuf;
	//Buffers for TLS connection
	char* rxbuf = malloc(4096);
	char* txbuf = malloc(4096);
	//Stdin Buffers
	char* inbuf = malloc(1024);
	char* inbuf2 = malloc(1024);
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
				encbuf = (char*)encryptmsg(inbuf,(unsigned char*)inbuf2,priv_evp,db); //"user" would be the receiving username
				if(!encbuf)break;
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
					sscso* obj = SSCS_open(rxbuf);
					char* rsapub64 = SSCS_object_string(obj,"b64rsa");
					int rsalen = SSCS_object_int(obj,"rsalen");
					sqlite3_prepare_v2(db,"insert into knownusers(uid,username,rsapub64,rsalen)values(NULL,?1,?2,?3);",-1,&stmt,NULL);
					sqlite3_bind_text(stmt,1,inbuf,-1,0);
					sqlite3_bind_text(stmt,2,(const char*)rsapub64,-1,0);
					sqlite3_bind_int(stmt,3,rsalen);
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);
				//	SSCS_data_release(&data);
					SSCS_release(&obj);
							
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
				if(strcmp(recvbuf2,"ERROR") == 0)break;
				sscsl* list = SSCS_list_open(recvbuf2);
				int i = 0;
				while(1){
					i++;	
					sscsd* prebuf =	SSCS_list_data(list,i);	
					if(prebuf == NULL)break;
					//printf("Got message (index %i) %s\n",i,prebuf->data);
					sscso* obj2 = SSCS_open(prebuf->data);
					SSCS_data_release(&prebuf);
					char* sender = SSCS_object_string(obj2,"sender");
					//if(sender == NULL)pexit("did not find label sender");
					decbuf = (char*)decryptmsg(obj2->buf_ptr,priv_evp,db);	
					if(decbuf)printf("Decrypted Message from %s: %s\n",sender,decbuf); 
					SSCS_release(&obj2);
					free(sender);
					if(decbuf)free(decbuf);
				}
				SSCS_list_release(&list);
				break;
		default: //Do nothing
				break;
		};
		
	}
#endif /* SSCS_CLI */
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


