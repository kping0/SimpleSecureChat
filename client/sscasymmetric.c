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


int LoadKeyPair(EVP_PKEY* pubKey, EVP_PKEY* privKey,char* path4pubkey,char* path4privkey){
	/*
	* This Function reads the Public&Private key from files into (initialized)EVP_PKEY objects...
	*/
	BIO* rsa_pub_bio = BIO_new_file(path4pubkey,"r");
	if(rsa_pub_bio == NULL){
		puts("error loading public key!"); //error checking
		return 0;	
	}
	RSA* rsa_pub = RSA_new();
	PEM_read_bio_RSAPublicKey(rsa_pub_bio,&rsa_pub,NULL,NULL);
	BIO_free(rsa_pub_bio);	
	RSA_blinding_on(rsa_pub,NULL);
	EVP_PKEY_assign_RSA(pubKey,rsa_pub);
	
	BIO* rsa_priv_bio = BIO_new_file(path4privkey,"r");
	if(rsa_priv_bio == NULL){
		puts("error loading private key!"); //error checking
		return 0;	
	}
	RSA* rsa_priv = RSA_new();
	PEM_read_bio_RSAPrivateKey(rsa_priv_bio, &rsa_priv,NULL,NULL);
	BIO_free(rsa_priv_bio);
	RSA_blinding_on(rsa_priv,NULL);
	if(RSA_check_key(rsa_priv) <= 0){
		puts("Invalid Private Key");
		return 0;	
	}
	EVP_PKEY_assign_RSA(privKey,rsa_priv); 
	return 1;

}

void CreateKeyPair(char* path4pubkey,char* path4privkey,int keysize){
    RSA* rsa = RSA_new();
    BIGNUM* prime = BN_new();
    BN_set_word(prime,RSA_F4);
    RSA_generate_key_ex(rsa,keysize,prime,NULL);
    int check_key = RSA_check_key(rsa);
    while (check_key <= 0) {
        puts( "error...regenerating...");
	RSA_generate_key_ex(rsa,8192,prime,NULL);
        check_key = RSA_check_key(rsa);
    }
    RSA_blinding_on(rsa, NULL);

    // write out pem-encoded public key ----
    BIO* rsaPublicBio = BIO_new_file(path4pubkey, "w");
    PEM_write_bio_RSAPublicKey(rsaPublicBio, rsa);

    // write out pem-encoded encrypted private key ----
    BIO* rsaPrivateBio = BIO_new_file(path4privkey, "w");
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
