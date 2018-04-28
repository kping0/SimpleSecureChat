
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
	fprintf(stderr,"Error: %s\n",errormsg);
	exit(1);
}
void exit_mysql_err(MYSQL* con){ //print exit message and exit
	fprintf(stderr,"Error: %s\n",mysql_error(con));
	mysql_close(con);
	exit(1);	
}

int my_mysql_query(MYSQL* con,char* query){ //mysql_query() with error checking
	int retval = mysql_query(con,query);
	if(retval)exit_mysql_err(con);
	return retval;
}

void init_DB(void){ //prepare database
	fprintf(stdout,"Info: MySQL client version-> %s\n",mysql_get_client_info());
	MYSQL* con = mysql_init(NULL);
	if(!con){
		fprintf(stderr,"Error: %s\n",mysql_error(con));
		exit(1);
	}
	if(!mysql_real_connect(con,SSCDB_SRV,SSCDB_USR,SSCDB_PASS,NULL,0,NULL,0))exit_mysql_err(con);
	if(mysql_query(con,"use SSCServerDB")){
		fprintf(stderr,"Error: ? Server DB not found, First Time Run? -> Trying to Create Database\n");
		if(mysql_query(con,"CREATE DATABASE SSCServerDB"))exit_mysql_err(con);
		if(mysql_query(con,"use SSCServerDB"))exit_mysql_err(con);
		
	}
//Create Messages Database & KnownUsers Database
	my_mysql_query(con,"CREATE TABLE IF NOT EXISTS MESSAGES(MSGID INT AUTO_INCREMENT PRIMARY KEY,RECVUID INTEGER NOT NULL,MESSAGE TEXT NOT NULL)");
	my_mysql_query(con,"CREATE TABLE IF NOT EXISTS KNOWNUSERS(UID INT AUTO_INCREMENT PRIMARY KEY,USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL,RSALEN INT NOT NULL,AUTHKEY TEXT NOT NULL)");
	mysql_close(con); 
	return;
}

MYSQL* get_handle_DB(void){ //return active handle to database
	MYSQL* con = mysql_init(NULL);
	if(!con){
		fprintf(stderr,"Error: %s\n",mysql_error(con));
		exit(1);
	}
	if(!mysql_real_connect(con,SSCDB_SRV,SSCDB_USR,SSCDB_PASS,"SSCServerDB",0,NULL,0))exit_mysql_err(con);
	return con;	
}

int create_socket(int port){ //bind socket s to port and return socket s
    int s = 0;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf(stderr,"Error: Unable to create socket\n");
	exit(EXIT_FAILURE);
    }
    int enable = 1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&enable,sizeof(int));
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	fprintf(stderr,"Error: Unable to bind\n");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	fprintf(stderr,"Error: Unable to listen\n");
	exit(EXIT_FAILURE);
    }
    #ifdef SSC_VERIFY_VARIABLES
    assert(s != 0);
    #endif
    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	fprintf(stderr,"Error: Unable to create SSL context\n");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int checkforUser(char* username,MYSQL* db){ //Check if user exists in database, returns 1 if true, 0 if false
//Create Variables for STUPID bind system for MYSQL
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt)return 1; //make sure user is not added if an error occurs
	char* statement = "SELECT UID FROM KNOWNUSERS WHERE username=?";
	if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
		fprintf(stderr,"Error: stmt prepare failed (%s)\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
		exit(1);
	}
	MYSQL_BIND bind[1];
	memset(bind,0,sizeof(bind));
	bind[0].buffer_type=MYSQL_TYPE_STRING;
	bind[0].buffer=username;
	bind[0].buffer_length=strlen(username);
	bind[0].is_null=0;
	bind[0].length=0;
	if(mysql_stmt_bind_param(stmt,bind)){
		fprintf(stderr,"Error: stmt bind param failed (%s)\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
		exit(1);
	}
	if(mysql_stmt_execute(stmt)){
		fprintf(stderr,"Error: stmt exec failed int checkforUser(): %s\n",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(db);
		exit(1);
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
}
int addUser2DB(char* username,char* b64rsa,int rsalen,char* authkey,MYSQL* db){ //Add User to database, returns 1 on success,0 on error
//        printf("Trying to add user: %s,b64rsa is %s, w len of %i, authkey is %s\n",username,b64rsa,rsalen,authkey);
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt){
                fprintf(stderr,"Error: Failed to initialize stmt -> addUser2DB\n");
                mysql_close(db);
                exit(1);
        }
      char* statement = "INSERT INTO KNOWNUSERS VALUES(NULL,?,?,?,?)";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: stmt prepare failed (%s) -> addUser2DB \n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        MYSQL_BIND bind[4];
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
        bind[3].buffer=authkey;
        bind[3].buffer_length=strlen(authkey);
        bind[3].is_null=0;
        bind[3].length=0;
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: binding stmt param (%s) -> addUser2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: stmt exec failed (%s) -> addUser2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        mysql_stmt_close(stmt);
        return 1; //return success
}

void ssc_sig_handler(int sig){ //Function to handle signals
		if(sig == SIGINT || sig == SIGABRT || sig == SIGTERM){
			fprintf(stdout,"\nCaught Signal... Exiting\n");
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
}

int getUserUID(char* username,MYSQL *db){ //gets uid for the username it is passed in args (to add a message to db for ex.)
       if(!username){
                mysql_close(db);
                exit(1);
        }
        MYSQL_STMT* stmt;
        stmt = mysql_stmt_init(db);
        if(!stmt){
                fprintf(stderr,"Error: mysql_stmt_init out of mem ->getUserUID\n");
                mysql_close(db);
                exit(1);
        }
        char* statement = "SELECT UID FROM KNOWNUSERS WHERE USERNAME = ?";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: mysql_stmt_prepare() error (%s) -> getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: mysql_stmt_bind_param err (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        int usruid = -1;
        MYSQL_BIND result[1];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_LONG;
        result[0].buffer=&usruid;

        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: mysql_stmt_execute err (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_bind_result(stmt,result)){
                fprintf(stderr,"Error: mysql_stmt_bind_result() err(%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_store_result(stmt)){
                fprintf(stderr,"Error: mysql_stmt_store_result() err(%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_fetch(stmt)){
                fprintf(stderr,"Error: mysql_stmt_fetch() error / maybe user is not in db (%s)->getUserUID\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return -1;
        }
        else{
                mysql_stmt_close(stmt);
                return usruid;
        }
        return -1;
}

int AddMSG2DB(MYSQL* db,char* recipient,unsigned char* message){ //Adds a message to the database, returns 1 on success, 0 on error
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                fprintf(stderr,"Error: mysql_stmt_init out of mem->addMsg2DB\n");
                mysql_close(db);
                exit(1);
        }
        char* statement = "INSERT INTO MESSAGES VALUES(NULL,?,?)";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: mysql_stmt_prepare err (%s)->addMsg2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        int recvuid = getUserUID(recipient,db);
        MYSQL_BIND bind[2];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_LONG;
        bind[0].buffer=&recvuid;
        bind[0].buffer_length=sizeof(int);
        bind[1].buffer_type=MYSQL_TYPE_STRING;
        bind[1].buffer=message;
        bind[1].buffer_length=strlen(message);
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: mysql_stmt_bind_param err (%s)->AddMSG2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        //printf("Username %s , %i with msg %s\n",recipient,recvuid,message);
        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: mysql_stmt_execute() err (%s)->addMSG2DB\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        else{
                mysql_stmt_close(stmt);
                return 1;
        }
        return 0;
}

const char* GetEncodedRSA(char* username, MYSQL* db){ //Functions that returns an encoded user RSA key.

        char* newline = strchr(username,'\n');
        if( newline ) *newline = 0;
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                fprintf(stderr,"Error: mysql_stmt_init out of mem ->GetEncodedRSA\n");
                mysql_close(db);
                exit(1);
        }
        char* statement = "SELECT RSAPUB64,RSALEN FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: mysql_stmt_prepare() error (%s) -> GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: mysql_stmt_bind_param err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        char* rsapub64 = NULL;
        int rsalen = -1;
        int rsapub64_len = 0;
        MYSQL_BIND result[2];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&rsapub64_len; //get length to allocate buffer
        result[1].buffer_type=MYSQL_TYPE_LONG;
        result[1].buffer=&rsalen;

        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: mysql_stmt_execute err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_bind_result(stmt,result)){
                fprintf(stderr,"Error: mysql_stmt_bind_result() err(%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_store_result(stmt)){
                fprintf(stderr,"Error: mysql_stmt_store_result() err(%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        int mysql_fetch_rv = mysql_stmt_fetch(stmt);
        if(mysql_fetch_rv && !(mysql_fetch_rv == MYSQL_DATA_TRUNCATED)){ //if error occurred and it was NOT MYSQL_DATA_TRUNCATED
                fprintf(stderr,"Error: mysql_stmt_fetch err (%s)->GetEncodedRSA\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        if(rsapub64_len > 0){
                rsapub64 = malloc(rsapub64_len); //allocate buffer for string
                memset(result,0,sizeof(result)); //reset result so that rsalen does not get reset
                result[0].buffer=rsapub64;
                result[0].buffer_length=rsapub64_len;
                mysql_stmt_fetch_column(stmt,result,0,0); //get string
        }
        else{
                mysql_stmt_close(stmt);
#ifdef DEBUG
               fprintf(stderr,"Error: rsapub64_len <= 0,maybe user \"%s\" does not exist?->GetEncodedRSA\n",username);
#endif /* DEBUG */
                return NULL;
        }
#ifdef DEBUG
        fprintf(stdout,"Length returned by GetEncodedRSA is %i->>%s)\n",rsalen,rsapub64);
#endif /* DEBUG */
        int messagep = GETRSA_RSP;
        sscso* obj = SSCS_object();
        SSCS_object_add_data(obj,"msgp",&messagep,sizeof(int));
        SSCS_object_add_data(obj,"b64rsa",rsapub64,rsapub64_len);
        SSCS_object_add_data(obj,"rsalen",&rsalen,sizeof(int));
        const char* retptr = SSCS_object_encoded(obj);
//cleanup
        SSCS_release(&obj);
        free(rsapub64);
        mysql_stmt_close(stmt);
        return retptr;
}

char* GetUserMessagesSRV(char* username,MYSQL* db){ //Returns buffer with encoded user messages
        int usruid = getUserUID(username,db);
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                fprintf(stderr,"Error: mysql_stmt_init out of mem ->GetUserMessagesSRV\n");
                mysql_close(db);
                exit(1);
        }
        char* statement = "SELECT MESSAGE FROM MESSAGES WHERE RECVUID = ?";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: mysql_stmt_prepare err (%s) ->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_LONG;
        bind[0].buffer=&usruid;
        bind[0].buffer_length=sizeof(int);
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: mysql_stmt_bind_param err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: mysql_stmt_execute err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        MYSQL_BIND result[1];
        int msglength = 0;
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&msglength;
        if(mysql_stmt_bind_result(stmt,result)){
                fprintf(stderr,"Error: mysql_stmt_bind_result() err(%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        if(mysql_stmt_store_result(stmt)){
                fprintf(stderr,"Error: mysql_stmt_store_result() err(%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
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
                fprintf(stderr,"Error: mysql_stmt_fetch err (%s)->GetUserMessagesSRV\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        if(msglength > 0){
                msgbuf = malloc(msglength); //allocate buffer for string
                memset(result,0,sizeof(result)); //reset result so that rsalen does not get reset
                result[0].buffer=msgbuf;
                result[0].buffer_length = msglength;
                mysql_stmt_fetch_column(stmt,result,0,0); //get string
        }
        else{
                mysql_stmt_close(stmt);
                break;
        }
        SSCS_list_add_data(list,msgbuf,msglength);
        free(msgbuf);
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
                fprintf(stderr,"Error: mysql_stmt_prepare2 err (%s) ->GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                mysql_stmt_close(stmt2);
                mysql_close(db);
                exit(1);
        }
        MYSQL_BIND bind2[1];
        memset(bind2,0,sizeof(bind2));
        bind2[0].buffer_type=MYSQL_TYPE_LONG;
        bind2[0].buffer=&usruid;
        bind2[0].buffer_length=sizeof(int);
        if(mysql_stmt_bind_param(stmt2,bind2)){
                fprintf(stderr,"Error: mysql_stmt_bind_param2 err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                free(retptr);
                mysql_stmt_close(stmt2);
                mysql_close(db);
                exit(1);
        }
        if(mysql_stmt_execute(stmt2)){
                fprintf(stderr,"Error: mysql_stmt_execute2 err (%s) -> GetUserMessagesSRV\n",mysql_stmt_error(stmt2));
                free(retptr);
                mysql_stmt_close(stmt2);
                mysql_close(db);
                exit(1);
        }
        mysql_stmt_close(stmt2);

        return retptr;
}


void childexit_handler(int sig){ //Is registered to the Signal SIGCHLD, kills all zombie processes
	(void)sig;
	int saved_errno = errno;
	while(waitpid((pid_t)(-1),0,WNOHANG) > 0){}
	errno = saved_errno;
}

char* getUserAuthKey(char* username, MYSQL* db){
        char* newline = strchr(username,'\n');
        if( newline ) *newline = 0;
        MYSQL_STMT* stmt = mysql_stmt_init(db);
        if(!stmt){
                fprintf(stderr,"Error: mysql_stmt_init out of mem ->getUserAuthKey\n");
                mysql_close(db);
                exit(1);
        }
        char* statement = "SELECT AUTHKEY FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1";
        if(mysql_stmt_prepare(stmt,statement,strlen(statement))){
                fprintf(stderr,"Error: mysql_stmt_prepare() error (%s) -> getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        MYSQL_BIND bind[1];
        memset(bind,0,sizeof(bind));
        bind[0].buffer_type=MYSQL_TYPE_STRING;
        bind[0].buffer=username;
        bind[0].buffer_length=strlen(username);
        if(mysql_stmt_bind_param(stmt,bind)){
                fprintf(stderr,"Error: mysql_stmt_bind_param err (%s)->getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        char* authkey = NULL;
        int authkey_len = 0;
        MYSQL_BIND result[1];
        memset(result,0,sizeof(result));
        result[0].buffer_type=MYSQL_TYPE_STRING;
        result[0].length=&authkey_len; //get length to allocate buffer

        if(mysql_stmt_execute(stmt)){
                fprintf(stderr,"Error: mysql_stmt_execute err (%s)->getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_bind_result(stmt,result)){
                fprintf(stderr,"Error: mysql_stmt_bind_result() err(%s)->getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }

        if(mysql_stmt_store_result(stmt)){
                fprintf(stderr,"Error: mysql_stmt_store_result() err(%s)->getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                mysql_close(db);
                exit(1);
        }
        int mysql_fetch_rv = mysql_stmt_fetch(stmt);
        if(mysql_fetch_rv && !(mysql_fetch_rv == MYSQL_DATA_TRUNCATED)){ //if error occurred and it was NOT MYSQL_DATA_TRUNCATED
                fprintf(stderr,"Error: mysql_stmt_fetch err (%s)->getUserAuthKey\n",mysql_stmt_error(stmt));
                mysql_stmt_close(stmt);
                return NULL;
        }
        if(authkey_len >= 256){
                authkey = malloc(authkey_len); //allocate buffer for string
                memset(result,0,sizeof(result)); //reset result 
                result[0].buffer=MYSQL_TYPE_STRING;
                result[0].buffer=authkey;
                result[0].buffer_length=authkey_len;
                mysql_stmt_fetch_column(stmt,result,0,0); //get string
        }
        else{
                mysql_stmt_close(stmt);
#ifdef DEBUG
                fprintf(stderr,"Error: authkey_ley !>= 256 maybe user \"%s\" does not exist?->getUserAuthKey\n",username);
#endif /* DEBUG */
                return NULL;
        }
#ifdef DEBUG
//        fprintf(stdout,": getUserAuthKey.authkey->>%s)\n",authkey);
#endif /* DEBUG */
        mysql_stmt_close(stmt);
        return authkey;
}

