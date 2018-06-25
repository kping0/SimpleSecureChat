
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

#include "sscsrvfunc.h"

void pexit(char* errormsg){
	cerror(" %s\n",errormsg);
#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
} /* pexit */

void exit_mysql_err(MYSQL* con){ //print exit message and exit
	cerror(" %s\n",mysql_error(con));
	mysql_close(con);
	#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif	
} /* exit_mysql_err */

int my_mysql_query(MYSQL* con,char* query){ //mysql_query() with error checking
	int retval = mysql_query(con,query);
	if(retval)exit_mysql_err(con);
	return retval;
} /* my_mysql_query */

void init_DB(void){ //prepare database
	cinfo("MySQL client version-> %s",mysql_get_client_info());
	char* srvhost = sconfig_get_str(config,"SSCDB_SRV");	
	char* srvuser = sconfig_get_str(config,"SSCDB_USR");
	char* srvpass = sconfig_get_str(config,"SSCDB_PASS");
	cinfo("Trying to get a session started with the MySQL server -- %s::%s",srvhost,srvuser);
	MYSQL* con = mysql_init(NULL);
	if(!con){
		cerror(" %s\n",mysql_error(con));
		exit(1);
	}
	if(!mysql_real_connect(con,srvhost,srvuser,srvpass,NULL,0,NULL,0))exit_mysql_err(con);
	if(mysql_query(con,"use SSCServerDB")){
		cinfo(" ? Server DB not found, First Time Run? -> Trying to Create Database\n");
		if(mysql_query(con,"CREATE DATABASE SSCServerDB"))exit_mysql_err(con);
		if(mysql_query(con,"use SSCServerDB"))exit_mysql_err(con);
		
	}
//Create Messages Database & KnownUsers Database
	my_mysql_query(con,"CREATE TABLE IF NOT EXISTS MESSAGES(MSGID INT AUTO_INCREMENT PRIMARY KEY,RECVUID INTEGER NOT NULL,MESSAGE TEXT NOT NULL)");
	my_mysql_query(con,"CREATE TABLE IF NOT EXISTS KNOWNUSERS(UID INT AUTO_INCREMENT PRIMARY KEY,USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL,RSALEN INT NOT NULL,SHA256 TEXT NOT NULL,SALT TEXT NOT NULL)");
	mysql_close(con); 
	cfree(srvhost);
	cfree(srvuser);
	cfree(srvpass);
	return;
} /* init_DB */

MYSQL* get_handle_DB(void){ //return active handle to database
	MYSQL* con = mysql_init(NULL);
	if(!con){
		cerror(" %s\n",mysql_error(con));
#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
	}
	char* srvhost = sconfig_get_str(config,"SSCDB_SRV");	
	char* srvuser = sconfig_get_str(config,"SSCDB_USR");
	char* srvpass = sconfig_get_str(config,"SSCDB_PASS");
	if(!mysql_real_connect(con,srvhost,srvuser,srvpass,"SSCServerDB",0,NULL,0))exit_mysql_err(con);
	cfree(srvhost);
	cfree(srvuser);
	cfree(srvpass);
	return con;	
} /* get_handle_DB */

int create_socket(int port){ //bind socket s to port and return socket s
    int s = 0;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	cerror(" Unable to create socket\n");
	exit(EXIT_FAILURE);
    }
    int enable = 1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&enable,sizeof(int));
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	cerror(" Unable to bind, is server already running?\n");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	cerror(" Unable to listen\n");
	exit(EXIT_FAILURE);
    }
    assert(s != 0);
    return s;
} /* create_socket */

void init_openssl(){ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
} /* init_openssl */

void cleanup_openssl(){
    EVP_cleanup();
} /* cleanup_openssl */

SSL_CTX *create_context(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	cerror(" Unable to create SSL context\n");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
} /* create_context */

void configure_context(SSL_CTX *ctx){
    char* keypw = sconfig_get_str(config,"SSCS_KEYFILE_PW");
    char* certfile = sconfig_get_str(config,"SSCS_CERTFILE");
    char* keyfile = sconfig_get_str(config,"SSCS_KEYFILE");
    SSL_CTX_set_default_passwd_cb_userdata(ctx,keypw);
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx,certfile , SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cfree(keypw);
        cfree(certfile);
 	cfree(keyfile);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx,keyfile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        cfree(keypw);
        cfree(certfile);
 	cfree(keyfile);
	exit(EXIT_FAILURE);
    }

    cfree(keypw);
    cfree(certfile);
    cfree(keyfile);
    return;
} /* configure_context */

int checkforUser(char* username,MYSQL* db){ //Check if user exists in database, returns 1 if true, 0 if false
//Create Variables for STUPID bind system for MYSQL
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt)return 1; //make sure user is not added if an error occurs
	char* statement = "SELECT UID FROM KNOWNUSERS WHERE username=?";
	if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
		cerror(" stmt prepare failed (%s)\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
	}
	MYSQL_BIND bind[1];
	memset(bind,0,sizeof(bind));
	bind[0].buffer_type=MYSQL_TYPE_STRING;
	bind[0].buffer=username;
	bind[0].buffer_length=strlen(username);
	bind[0].is_null=0;
	bind[0].length=0;
	if(mysql_stmt_bind_param(stmt,bind)){
		cerror(" stmt bind param failed (%s)\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
	}
	if(mysql_stmt_execute(stmt)){
		cerror(" stmt exec failed int checkforUser(): %s\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
	}
	if(!mysql_stmt_fetch(stmt)){
		//User exits
		mysql_stmt_close(stmt);
		return 1;
	}
	else{
		//User does not exist
		mysql_stmt_close(stmt);
		return 0;
	}
} /* checkforUser */

int addUser2DB(char* username,char* b64rsa,int rsalen,char* authkey,MYSQL* db){ //Add User to database, returns 1 on success,0 on error
//        printf("Trying to add user: %s,b64rsa is %s, w len of %i, authkey is %s\n",username,b64rsa,rsalen,authkey);
	
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt){
                cerror(" Failed to initialize stmt -> addUser2DB\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
      char* statement = "INSERT INTO KNOWNUSERS VALUES(NULL,?,?,?,?,?)";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" stmt prepare failed (%s) -> addUser2DB \n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
	SSCS_HASH* hash = SSCS_createhash((byte*)authkey,strlen(authkey));
        MYSQL_BIND bind[5];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        bind[0].is_null=0;
        bind[0].length=0;
        bind[1].buffer_type=MYSQL_TYPE_STRING;
        bind[1].buffer=b64rsa;
        bind[1].buffer_length=strlen(b64rsa);
        bind[1].is_null=0;
        bind[1].length=0;
        bind[2].buffer_type=MYSQL_TYPE_LONG;
        bind[2].buffer=&rsalen;
        bind[2].buffer_length=sizeof(int);
        bind[2].is_null=0;
        bind[2].length=0;
	bind[3].buffer_type=MYSQL_TYPE_STRING;
	bind[3].buffer=hash->hash;
	bind[3].buffer_length=hash->hashl;
	bind[4].buffer_type=MYSQL_TYPE_STRING;
	bind[4].buffer=hash->salt;
	bind[4].buffer_length=hash->saltl;
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" binding stmt param (%s) -> addUser2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_execute(stmt)){
                cerror(" stmt exec failed (%s) -> addUser2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        mysql_stmt_close(stmt);
	SSCS_freehash(&hash);
        return 1; //return success
} /* addUser2DB */

void ssc_sig_handler(int sig){ //Function to handle signals
		if(sig == SIGINT || sig == SIGABRT || sig == SIGTERM){
			cdebug("\nCaught Signal... Exiting\n");
			close(sock);
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
} /* ssc_sig_handler */

int getUserUID(char* username,MYSQL *db){ //gets uid for the username it is passed in args (to add a message to db for ex.)
       if(!username){
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_STMT* stmt;
        stmt = mysql_stmt_init(db);
        if(!stmt){
                cerror(" mysql_stmt_init out of mem ->getUserUID\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        char* statement = "SELECT UID FROM KNOWNUSERS WHERE USERNAME = ?";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" mysql_stmt_prepare() error (%s) -> getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" mysql_stmt_bind_param err (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        int usruid = -1;
        MYSQL_BIND result[1];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_LONG;
        result[0].buffer=&usruid;

        if(mysql_stmt_execute(stmt)){
                cerror(" mysql_stmt_execute err (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_bind_result(stmt,result)){
                cerror(" mysql_stmt_bind_result() err(%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_store_result(stmt)){
                cerror(" mysql_stmt_store_result() err(%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_fetch(stmt)){
                cerror(" mysql_stmt_fetch() error / maybe user is not in db (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return -1;
        }
        else{
                mysql_stmt_close(stmt);
                return usruid;
        }
        return -1;
} /* getUserUID */

int AddMSG2DB(MYSQL* db,char* recipient,unsigned char* message){ //Adds a message to the database, returns 1 on success, 0 on error
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                cerror(" mysql_stmt_init out of mem->addMsg2DB\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        char* statement = "INSERT INTO MESSAGES VALUES(NULL,?,?)";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" mysql_stmt_prepare err (%s)->addMsg2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        int recvuid = getUserUID(recipient,db);
        MYSQL_BIND bind[2];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_LONG;
        bind[0].buffer=&recvuid;
        bind[0].buffer_length=sizeof(int);
        bind[1].buffer_type=MYSQL_TYPE_STRING;
        bind[1].buffer=message;
        bind[1].buffer_length=(size_t)strlen((const char*)message);
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" mysql_stmt_bind_param err (%s)->AddMSG2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        //printf("Username %s , %i with msg %s\n",recipient,recvuid,message);
        if(mysql_stmt_execute(stmt)){
                cerror(" mysql_stmt_execute() err (%s)->addMSG2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        else{
                mysql_stmt_close(stmt);
                return 1;
        }
        return 0;
} /* AddMSG2DB */

const char* GetEncodedRSA(char* username, MYSQL* db){ //Functions that returns an encoded user RSA key.

        char* newline = strchr(username,'\n');
        if( newline ) *newline = 0;
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                cerror(" mysql_stmt_init out of mem ->GetEncodedRSA\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        char* statement = "SELECT RSAPUB64,RSALEN FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" mysql_stmt_prepare() error (%s) -> GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" mysql_stmt_bind_param err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        byte* rsapub64 = NULL;
        size_t rsalen = -1;
        size_t rsapub64_len = 0;
        MYSQL_BIND result[2];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&rsapub64_len; //get length to allocate buffer
        result[1].buffer_type=MYSQL_TYPE_LONG;
        result[1].buffer=&rsalen;

        if(mysql_stmt_execute(stmt)){
                cerror(" mysql_stmt_execute err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_bind_result(stmt,result)){
                cerror(" mysql_stmt_bind_result() err(%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_store_result(stmt)){
                cerror(" mysql_stmt_store_result() err(%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        int mysql_fetch_rv = mysql_stmt_fetch(stmt);
        if(mysql_fetch_rv && !(mysql_fetch_rv == MYSQL_DATA_TRUNCATED)){ //if error occurred and it was NOT MYSQL_DATA_TRUNCATED
                cerror(" mysql_stmt_fetch err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        if(rsapub64_len > 0){
                rsapub64 = cmalloc(rsapub64_len); //allocate buffer for string
                memset(result,0,sizeof(result)); //reset result so that rsalen does not get reset
                result[0].buffer=rsapub64;
                result[0].buffer_length=rsapub64_len;
                mysql_stmt_fetch_column(stmt,result,0,0); //get string
        }
        else{
                mysql_stmt_close(stmt);
               cdebug(" rsapub64_len <= 0,maybe user \"%s\" does not exist?->GetEncodedRSA\n",username);
                return NULL;
        }
        cdebug("Length returned by GetEncodedRSA is %i->>%s)\n",(int)rsalen,rsapub64);
        int messagep = GETRSA_RSP;
        sscso* obj = SSCS_object();
        SSCS_object_add_data(obj,"msgp",(byte*)&messagep,sizeof(int));
        SSCS_object_add_data(obj,"b64rsa",rsapub64,rsapub64_len);
        SSCS_object_add_data(obj,"rsalen",(byte*)&rsalen,sizeof(int));
        const char* retptr = SSCS_object_encoded(obj);
//cleanup
        SSCS_release(&obj);
        cfree(rsapub64);
        mysql_stmt_close(stmt);
        return retptr;
} /* GetEncodedRSA */

char* GetUserMessagesSRV(char* username,MYSQL* db){ //Returns buffer with encoded user messages
        int usruid = getUserUID(username,db);
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                cerror(" mysql_stmt_init out of mem ->GetUserMessagesSRV\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        char* statement = "SELECT MESSAGE FROM MESSAGES WHERE RECVUID = ?";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" mysql_stmt_prepare err (%s) ->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_LONG;
        bind[0].buffer=&usruid;
        bind[0].buffer_length=sizeof(int);
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" mysql_stmt_bind_param err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        if(mysql_stmt_execute(stmt)){
                cerror(" mysql_stmt_execute err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_BIND result[1];
        size_t msglength = 0;
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&msglength;
        if(mysql_stmt_bind_result(stmt,result)){
                cerror(" mysql_stmt_bind_result() err(%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        if(mysql_stmt_store_result(stmt)){
                cerror(" mysql_stmt_store_result() err(%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        sscsl* list = SSCS_list();
while(1){
        msglength = 0;
        int mysql_fetch_rv = mysql_stmt_fetch(stmt);
        char* msgbuf = NULL;

        if((mysql_fetch_rv == MYSQL_NO_DATA)){ //If no data exists break
                mysql_stmt_close(stmt);
                break;
        }

        if(mysql_fetch_rv && !(mysql_fetch_rv == MYSQL_DATA_TRUNCATED)){ //if error occurred and it was NOT MYSQL_DATA_TRUNCATED
                cerror(" mysql_stmt_fetch err (%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        if(msglength > 0){
                msgbuf = cmalloc(msglength); //allocate buffer for string
                memset(result,0,sizeof(result)); //reset result so that rsalen does not get reset
                result[0].buffer=msgbuf;
                result[0].buffer_length = msglength;
                mysql_stmt_fetch_column(stmt,result,0,0); //get string
        }
        else{
                mysql_stmt_close(stmt);
                break;
        }
        SSCS_list_add_data(list,(byte*)msgbuf,msglength);
        cfree(msgbuf);
        msgbuf = NULL;
}
        char* retptr = SSCS_list_encoded(list);
	if(!retptr)pexit("retptr is NULL -> GetUserMessagesSRV");
        SSCS_list_release(&list);
/* 
* Delete messages that were received;
*/
        MYSQL_STMT *stmt2 = mysql_stmt_init(db);
        char* statement2 = "DELETE FROM MESSAGES WHERE RECVUID = ?";
        if(mysql_stmt_prepare(stmt2,statement2,strlen(statement2))){
                cerror(" mysql_stmt_prepare2 err (%s) ->GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                mysql_stmt_close(stmt2);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_BIND bind2[1];
        memset(bind2,0,sizeof(bind2));
        bind2[0].buffer_type=MYSQL_TYPE_LONG;
        bind2[0].buffer=&usruid;
        bind2[0].buffer_length=sizeof(int);
        if(mysql_stmt_bind_param(stmt2,bind2)){
                cerror(" mysql_stmt_bind_param2 err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                cfree(retptr);
                mysql_stmt_close(stmt2);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        if(mysql_stmt_execute(stmt2)){
                cerror(" mysql_stmt_execute2 err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                cfree(retptr);
                mysql_stmt_close(stmt2);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        mysql_stmt_close(stmt2);
        return retptr;
} /* GetUserMessagesSRV */


void childexit_handler(int sig){ //Is registered to the Signal SIGCHLD, kills all zombie processes
	(void)sig;
	int saved_errno = errno;
	while(waitpid((pid_t)(-1),0,WNOHANG) > 0){}
	errno = saved_errno;
} /* childexit_handler */

SSCS_HASH* getUserAuthKeyHash(char* username, MYSQL* db){
        char* newline = strchr(username,'\n');
        if( newline ) *newline = 0;
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                cerror(" mysql_stmt_init out of mem ->getUserAuthKeyHash\n");
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        char* statement = "SELECT SHA256,SALT FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                cerror(" mysql_stmt_prepare() error (%s) -> getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                cerror(" mysql_stmt_bind_param err (%s)->getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        char* authkey = NULL;
        size_t authkey_len = 0;
	char* salt = NULL;
	size_t salt_len = 0;
        MYSQL_BIND result[2];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&authkey_len; //get length to allocate buffer
	result[1].buffer_type=MYSQL_TYPE_STRING;
	result[1].length=&salt_len;
        if(mysql_stmt_execute(stmt)){
                cerror(" mysql_stmt_execute err (%s)->getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_bind_result(stmt,result)){
                cerror(" mysql_stmt_bind_result() err(%s)->getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }

        if(mysql_stmt_store_result(stmt)){
                cerror(" mysql_stmt_store_result() err(%s)->getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                #ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
        }
        int mysql_fetch_rv = mysql_stmt_fetch(stmt);
        if(mysql_fetch_rv && !(mysql_fetch_rv == MYSQL_DATA_TRUNCATED)){ //if error occurred and it was NOT MYSQL_DATA_TRUNCATED
                cerror(" mysql_stmt_fetch err (%s)->getUserAuthKeyHash\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        authkey = cmalloc(authkey_len); //allocate buffer for string
	salt = cmalloc(salt_len);
        memset(result,0,sizeof(result)); //reset result 
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].buffer=authkey;
        result[0].buffer_length=authkey_len;
        mysql_stmt_fetch_column(stmt,result,0,0); //get string
	memset(result,0,sizeof(result));
	result[0].buffer_type=MYSQL_TYPE_STRING;
	result[0].buffer=salt;
	result[0].buffer_length=salt_len;	
	mysql_stmt_fetch_column(stmt,result,1,0); //get string
        mysql_stmt_close(stmt);
	SSCS_HASH* retstruct = cmalloc(sizeof(SSCS_HASH));
	retstruct->hash=(byte*)authkey;	
	retstruct->hashl=authkey_len;
	retstruct->salt=(byte*)salt;
	retstruct->saltl=salt_len;
	cdebug("Salt is %s\n",salt);

	return retstruct;
} /* getUserAuthKeyHash */

