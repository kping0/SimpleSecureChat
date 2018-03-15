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

#include <binn.h> //Data Serialization Library
#include <sqlite3.h> 

/* SOURCES  & MENTIONS
* https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
* https://wiki.openssl.org/
*
*/
/*
* Application Settings
*/

#define HOST_NAME "127.0.0.1" //Server IP
#define HOST_PORT "5050" //Server Port
#define HOST_CERT "public.pem" // Server public certificate (X509 Public Cert)
#define PUB_KEY "rsapublickey.pem" //Public Key location (Will be generated if not found)
#define PRIV_KEY "rsaprivatekey.pem" //Private Key location (Will be generated if not found)
#define DB_FNAME "sscdb.db" //SQLITE Database Filename

 /*
 *  structure used to passthrough OpenSSL objects through various functions (ex main()>>TLS_init())
 */
struct ssl_str{ 
	BIO *bio_obj;
	SSL *ssl_obj;
	SSL_CTX *ctx;
	const SSL_METHOD *sslmethod;
	int success;	
	};


/* SNIPPET FROM THE OPENSSL WIKI*/
int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
	if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, priv_key))
		return 0;
	if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return 0;
	plaintext_len = len;
	if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) return 0;
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

/* SNIPPET FROM THE OPENSSL WIKI*/
int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int ciphertext_len;
	int len;
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		return 0;
	if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return 0;
	ciphertext_len = len;
	if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) return 0;
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

/* https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
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


int TLS_conn(struct ssl_str *tls_vars){ //return 1 on success, 0 on error

	long chkv = 1; /*Variable for error checking*/

	/*
	* Init OpenSSL Library
	*/
	
	(void)SSL_library_init(); 
	SSL_load_error_strings(); 

	/*
	*Create Variables Used By OpenSSL
	*/

	tls_vars->bio_obj = NULL;
	tls_vars->ssl_obj = NULL;
	tls_vars->ctx = NULL;
	tls_vars->sslmethod = NULL;
	tls_vars->sslmethod = SSLv23_method();
	if(!(NULL != tls_vars->sslmethod)) return 0;
	tls_vars->ctx = SSL_CTX_new(tls_vars->sslmethod); /* Generate SSL_CTX*/
	if(!(tls_vars->ctx != NULL)) return 0;

	/*
	* Set options for validation(verify against HOST_CERT) & connection(!SSLv2 & !SSLv3 & !Compression)
	*/	

	SSL_CTX_set_verify(tls_vars->ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(tls_vars->ctx,1); 
	SSL_CTX_set_options(tls_vars->ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
	chkv = SSL_CTX_load_verify_locations(tls_vars->ctx,HOST_CERT,NULL); /*Verify Server Certificate*/
	if(!(1 == chkv)) return 0;

	/*
	* Set connection variables 
	*/	
	
	tls_vars->bio_obj = BIO_new_ssl_connect(tls_vars->ctx);
	if(!(tls_vars->bio_obj != NULL)) return 0;
	chkv = BIO_set_conn_hostname(tls_vars->bio_obj, HOST_NAME ":" HOST_PORT);
	if(!(1 == chkv)) return 0;
	BIO_get_ssl(tls_vars->bio_obj, &tls_vars->ssl_obj);
	if(!(tls_vars->bio_obj != NULL)) return 0;
	chkv = SSL_set_cipher_list(tls_vars->ssl_obj,"HIGH:!aNULL:!eNULL:!PSK:!MD5:!RC4:!SHA1");
	if(!(1 == chkv)) return 0;

	/* 
	* Connect && Do Handshake
	*/

	chkv = BIO_do_connect(tls_vars->bio_obj);
	if(!(1 == chkv)) return 0;	
	chkv =BIO_do_handshake(tls_vars->bio_obj);
	if(!(1 == chkv)) return 0;

	/*
	* Check for certificate
	*/	
	
	X509* cert_test = SSL_get_peer_certificate(tls_vars->ssl_obj);
	if(cert_test){
		X509_free(cert_test);
		}
	if(NULL == cert_test){
		puts("ERR_NO_CERT");
		return 0;
	}

	return 1;
}

int LoadKeyPair(EVP_PKEY* pubKey, EVP_PKEY* privKey){
	/*
	* This Function reads the Public&Private key from files into (initialized)EVP_PKEY objects...
	*/
	BIO* rsa_pub_bio = BIO_new_file(PUB_KEY,"r");
	if(rsa_pub_bio == NULL){
		puts("error loading public key!"); //error checking
		return 0;	
	}
	RSA* rsa_pub = RSA_new();
	PEM_read_bio_RSAPublicKey(rsa_pub_bio,&rsa_pub,NULL,NULL);
	BIO_free(rsa_pub_bio);	
	EVP_PKEY_assign_RSA(pubKey,rsa_pub);
	
	BIO* rsa_priv_bio = BIO_new_file(PRIV_KEY,"r");
	if(rsa_priv_bio == NULL){
		puts("error loading private key!"); //error checking
		return 0;	
	}
	RSA* rsa_priv = RSA_new();
	PEM_read_bio_RSAPrivateKey(rsa_priv_bio, &rsa_priv,NULL,NULL);
	BIO_free(rsa_priv_bio);
	EVP_PKEY_assign_RSA(privKey,rsa_priv); 
	if(RSA_check_key(rsa_priv) <= 0){
		puts("Invalid Private Key");
		return 0;	
	}
	return 1;

}

void CreateKeyPair(void){
    RSA* rsa = RSA_generate_key(4096, RSA_F4, NULL, 0);
    int check_key = RSA_check_key(rsa);
    while (check_key <= 0) {
        puts( "error...regenerating...");
        rsa = RSA_generate_key(4096, RSA_F4, NULL, 0);
        check_key = RSA_check_key(rsa);
    }
    RSA_blinding_on(rsa, NULL);

    // write out pem-encoded public key ----
    BIO* rsaPublicBio = BIO_new_file(PUB_KEY, "w");
    PEM_write_bio_RSAPublicKey(rsaPublicBio, rsa);

    // write out pem-encoded encrypted private key ----
    BIO* rsaPrivateBio = BIO_new_file(PRIV_KEY, "w");
    PEM_write_bio_RSAPrivateKey(rsaPrivateBio, rsa, NULL, NULL, 0, NULL, NULL);

    BIO_free(rsaPublicBio);
    BIO_free(rsaPrivateBio);
    RSA_free(rsa);
    return;
}

int test_keypair(EVP_PKEY* pubk_evp,EVP_PKEY* priv_evp){ //Also an example of how messages could be encrypted
	//encrypt test	
	unsigned char* msg = malloc(100);
	strncpy((char*)msg,"secret  test_message",100);

	unsigned char* ek = malloc(EVP_PKEY_size(pubk_evp));
	int ekl = EVP_PKEY_size(pubk_evp); 

	unsigned char* iv = malloc(EVP_MAX_IV_LENGTH);
	RAND_poll(); //Seed CGRNG 
	if(RAND_bytes(iv,EVP_MAX_IV_LENGTH) != 1){
		puts("Error getting CS-RNG for IV");	
		return 0;	
	}
	RAND_poll(); //Change Seed for CGRNG
	unsigned char*enc_buf = malloc(2000);
	int enc_len = envelope_seal(&pubk_evp,msg,strlen((const char*)msg),&ek,&ekl,iv,enc_buf); //encrypt
	if(enc_len <= 0){
		puts("ERROR IN TESTFUNCTION");
		return 0;	
	}
	//decrypt test
	unsigned char* dec_buf = malloc(2000);
	/*int dec_len =*/ envelope_open(priv_evp,enc_buf,enc_len,ek,ekl,iv,dec_buf); //decrypt
	if(strncmp((const char*)msg,(const char*)dec_buf,strlen((const char*)msg)) == 0){
		puts("Keypair Test OK");	
	}
	else{
		puts("Keypair Test ERROR");
		return 0;
	}
	return 1;
}

sqlite3* initDB(void){
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc = sqlite3_open(DB_FNAME,&db);
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

int DBUserInit(sqlite3 *db){ //check for own user & create if no found
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
		BIO* rsa_pub_bio = BIO_new_file(PUB_KEY,"r");
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


int main(void){
	puts("Starting secure chat application...");
	puts("Get the source at: ('https://www.github.com/kping0/simplesecurechat/client')");
	puts("Host your own server with ('https://.www.github.com/kping0/simplesecurechat/server')");
	//Setup SSL Connection
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(TLS_conn(tls_vars)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		BIO_write(tls_vars->bio_obj,"12345",5);
		puts("SSL/TLS OK");
		puts("Connected to " HOST_NAME ":" HOST_PORT " using server-cert: " HOST_CERT);
	}
	else{
		puts("SSL/TLS ERROR");	
	}
	//Load Keypair From Disk
	EVP_PKEY* pubk_evp = EVP_PKEY_new();
	EVP_PKEY* priv_evp = EVP_PKEY_new();
	if(!LoadKeyPair(pubk_evp,priv_evp)){
		puts("Loaded Keypair ERROR\nGenerating new keypair OK");
		EVP_PKEY_free(pubk_evp);
		EVP_PKEY_free(priv_evp);
		CreateKeyPair();
		puts("Please restart the binary to load your keypair");
		return 0;
		
	}
	else {
		puts("Loaded Keypair OK");
		test_keypair(pubk_evp,priv_evp);
	}
	//Load SQLITE Database
	sqlite3 *db = initDB();
	if(db != NULL){
		puts("Loaded User OK");
	}
	else{
		puts("Loading db ERROR");
		sqlite3_close(db);
		goto CLEANUP;	
	}
	if(DBUserInit(db) != 1){
		puts("userINIT ERROR");
		sqlite3_close(db);
		goto CLEANUP;
	}
	
	//EVP_PKEY *pubk_evp2 = get_pubk_username("username",db);
	//test_keypair(pubk_evp2,priv_evp);
	//EVP_PKEY_free(pubk_evp2);	

	
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
