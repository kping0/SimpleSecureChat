
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

#include "hashing.h"

byte* memncat(byte* first,size_t firstl,byte* second,size_t secondl){ //concatenates two blocks of memory 
	byte* finalbuffer = cmalloc(firstl+secondl);
	byte* writepointer = finalbuffer;
	memcpy(writepointer,first,firstl);
	writepointer+=firstl;
	memcpy(writepointer,second,secondl);
	return finalbuffer;
}

SSCS_HASH* SSCS_createhash(byte* data,size_t datal){
	byte salt[20]; 	
	byte hash[SHA512_DIGEST_LENGTH];

	RAND_poll();
	if(!RAND_bytes(salt,20))return NULL;
	size_t b64saltl = 0;
	byte* b64salt = mitbase64_encode(salt,20,&b64saltl);

	byte* salt_and_data = memncat(b64salt,b64saltl,data,datal);	
	memset(hash,0,SHA512_DIGEST_LENGTH);
	SHA512(salt_and_data,(b64saltl+datal),hash);

	size_t b64hashl = 0;
	byte* b64hash = mitbase64_encode(hash,SHA512_DIGEST_LENGTH,&b64hashl);

	SSCS_HASH* retstruct = cmalloc(sizeof(SSCS_HASH));
	retstruct->hash = b64hash;
	retstruct->hashl = b64hashl;
	retstruct->salt = b64salt;
	retstruct->saltl = b64saltl;
	cfree(salt_and_data);
	return retstruct;
}

int SSCS_comparehash(byte* data,size_t datal,SSCS_HASH* originalhash){
	byte* salt = originalhash->salt;
	size_t saltl = originalhash->saltl;
	byte* hash = originalhash->hash;
	size_t hashl = originalhash->hashl;	
	byte* salt_and_data = memncat(salt,saltl,data,datal);
	byte data_hash[SHA512_DIGEST_LENGTH];		
	memset(data_hash,0,SHA512_DIGEST_LENGTH);
	SHA512(salt_and_data,(saltl+datal),data_hash);
	size_t b64data_hash_len = 0;
	byte* b64data_hash = mitbase64_encode(data_hash,SHA512_DIGEST_LENGTH,&b64data_hash_len);
	if(b64data_hash_len != hashl){
		cfree(salt_and_data);
		cfree(b64data_hash);
		return SSCS_HASH_INVALID;
	}
	int result = memcmp(hash,b64data_hash,SHA512_DIGEST_LENGTH);
	cfree(salt_and_data);
	cfree(b64data_hash);
	if(result==0)return SSCS_HASH_VALID;
	return SSCS_HASH_INVALID;
}

void SSCS_freehash(SSCS_HASH** hash){
	cfree(((*hash)->hash));
	cfree(((*hash)->salt));
	cfree((*hash));
	*hash = NULL;
}

