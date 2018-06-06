
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

#include "msgfunc.h"

byte* encrypt_msg(byte* username,byte* message,EVP_PKEY* signingKey,sqlite3* db){ //returns b64 of binnobj that includes b64encryptedaeskey,aeskeylength,b64encrypedbuffer,encbuflen,b64iv,ivlen
	if(strlen((byte*)message) > 1024){
		fprintf(stderr,"Message too long(limit 1024)\n");
		return NULL;	
	}
	sscso* obj = SSCS_object();
	SSCS_object_add_data(obj,"recipient",(byte*)username,strlen((byte*)username));
	EVP_PKEY* userpubk = get_pubk_username(username,db);
	if(userpubk == NULL){
		fprintf(stderr,"Could not get Users Public Key, maybe not in DB?\n");
		SSCS_release(&obj);
		EVP_PKEY_free(userpubk);
		return NULL;
	}
	
	byte* ek = malloc(EVP_PKEY_size(userpubk));
	int ekl = EVP_PKEY_size(userpubk); 

	byte* iv = malloc(EVP_MAX_IV_LENGTH);
	RAND_poll();  
	if(RAND_bytes(iv,EVP_MAX_IV_LENGTH) != 1){
		fprintf(stderr,"Error getting CS-RNG for IV\n");	
		return NULL;	
	}
	RAND_poll();
	byte*enc_buf = malloc(2000);
	//A Way to impliment the sign-then-encrypt with good context protection

	sscso* sigmsg = SSCS_object();
	SSCS_object_add_data(sigmsg,"msg",(byte*)message,strlen((byte*)message));
	SSCS_object_add_data(sigmsg,"recipient",(byte*)username,strlen((byte*)username));
	byte *sig = NULL;
	size_t sigl = 0;
	int rc = sign_msg(sigmsg->buf_ptr,sigmsg->allocated,&sig,&sigl,signingKey); //Create Signature for message+recipient
	if(!(rc == 0)){
		fprintf(stderr,"error signing message\n");
		SSCS_release(&sigmsg);
		SSCS_release(&obj);
		free(iv);
		free(ek);
		free(enc_buf);
		free(sig);
		EVP_PKEY_free(userpubk);
		return NULL;	
	}
	sscso* sigmsg2 = SSCS_object();
	SSCS_object_add_data(sigmsg2,"sig",sig,sigl);
	SSCS_object_add_data(sigmsg2,"sscso",(byte*)sigmsg->buf_ptr,sigmsg->allocated);
	//Encrypt message 
	int enc_len = envelope_seal(&userpubk,(byte*)SSCS_object_encoded(sigmsg2),SSCS_object_encoded_size(sigmsg2),&ek,&ekl,iv,enc_buf);
	if(enc_len <= 0){
		fprintf(stderr,"Error Encrypting Message!\n");
		return NULL;	
	}
	int message_purpose = MSGSND;
	SSCS_object_add_data(obj,"msgp",(byte*)&message_purpose,sizeof(int));
	SSCS_object_add_data(obj,"ek",(byte*)ek,ekl);
	SSCS_object_add_data(obj,"enc_buf",enc_buf,enc_len);
	SSCS_object_add_data(obj,"iv",iv,EVP_MAX_IV_LENGTH);
	byte* retptr = SSCS_object_encoded(obj);
	//cleanup memory
	SSCS_release(&obj);
	SSCS_release(&sigmsg);
	SSCS_release(&sigmsg2);
	free(iv);
	free(ek);
	free(enc_buf);
	EVP_PKEY_free(userpubk);	

	return retptr;
}

	
byte* decrypt_msg(byte *encrypted_buffer,EVP_PKEY* privKey,sqlite3* db){ // Attempts to decrypt buffer with your private key
	if(encrypted_buffer == NULL){
		fprintf(stderr,"Error decrypting\n");
		return NULL;	
	}
	sscso* obj = SSCS_open((byte*)encrypted_buffer);
	sscsd* enc_buf_data = SSCS_object_data(obj,"enc_buf");
	if(!enc_buf_data)return NULL;
	byte* enc_buf = enc_buf_data->data;
	int enc_len = enc_buf_data->len;
	sscsd* ek_data = SSCS_object_data(obj,"ek");
	if(!ek_data)return NULL;
	byte* ek = ek_data->data;
	int ekl = ek_data->len;	
	sscsd* iv_data = SSCS_object_data(obj,"iv");
	if(!iv_data)return NULL;
	byte* iv = iv_data->data;

	byte* dec_buf = malloc(2000);
	memset(dec_buf,0,2000);
	
	int dec_len = envelope_open(privKey,enc_buf,enc_len,ek,ekl,iv,dec_buf);
	assert(dec_len > 0);

	sscso* obj2 = SSCS_open(dec_buf);
	sscsd* serializedobj3_data = SSCS_object_data(obj2,"sscso");
	byte* serializedobj3 = serializedobj3_data->data;
	int serializedobj3l = serializedobj3_data->len;
	sscso* obj3 = SSCS_open(serializedobj3);

	byte* sender = (byte*)SSCS_object_string(obj,"sender");
	EVP_PKEY *userpubk = get_pubk_username(sender,db);
	if(!userpubk){
		fprintf(stderr,"error retrieving public key for %s",sender);	
		free(sender);	
		free(dec_buf);
		SSCS_release(&obj);
		SSCS_release(&obj2);
		SSCS_release(&obj3);	
		SSCS_data_release(&serializedobj3_data);
		SSCS_data_release(&ek_data);
		SSCS_data_release(&enc_buf_data);
		SSCS_data_release(&iv_data);	
		return NULL;
	}
	sscsd* sig_data = SSCS_object_data(obj2,"sig");
	if(!sig_data){
		fprintf(stderr,"error retrieving public key for %s",sender);	
		free(sender);	
		free(dec_buf);
		SSCS_release(&obj);
		SSCS_release(&obj2);
		SSCS_release(&obj3);	
		SSCS_data_release(&serializedobj3_data);
		SSCS_data_release(&ek_data);
		SSCS_data_release(&enc_buf_data);
		SSCS_data_release(&iv_data);		
	}
	byte* sig = sig_data->data;
	int sigl = sig_data->len;

	int rc = verify_msg(serializedobj3,serializedobj3l,sig,sigl,userpubk);

	if(rc == 0){
#ifdef DEBUG
		fprintf(stdout,"Verified Signature\n");
#endif
	}	
	else{
#ifdef DEBUG
		fprintf(stderr,"failed to verify signature\n");
#endif
		return NULL;
	}

	byte* f_buf = (byte*)SSCS_object_string(obj3,"msg");

	SSCS_release(&obj);
	SSCS_release(&obj2);
	SSCS_release(&obj3);	
	SSCS_data_release(&sig_data);
	SSCS_data_release(&serializedobj3_data);
	SSCS_data_release(&ek_data);
	SSCS_data_release(&enc_buf_data);
	SSCS_data_release(&iv_data);
	free(sender);	
	EVP_PKEY_free(userpubk);
	
	
	return (byte*)f_buf;

}
/*
 * This Everything below this point is taken from the OpenSSL wiki -> the LICENSE for these functions is * https://www.openssl.org/source/license.html
 */
int sign_msg(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0); return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            fprintf(stderr,"EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname("SHA256");
        assert(md != NULL);
        if(md == NULL) {
            fprintf(stderr,"EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            fprintf(stderr,"EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            fprintf(stderr,"OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;
}

int verify_msg(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    if(!msg)assert(0);
    if(!mlen)assert(0);
    if(!sig)assert(0);
    if(!slen)assert(0);
    if(!pkey)assert(0); 
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            fprintf(stderr,"EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname("SHA256");
        assert(md != NULL);
        if(md == NULL) {
            fprintf(stderr,"EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Clear any errors for the call below */
        ERR_clear_error();
        
        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            fprintf(stderr,"EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;

}

