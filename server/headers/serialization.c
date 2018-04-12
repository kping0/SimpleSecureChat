#include <errno.h>
#include <stdlib.h> 
#include <stdio.h> 
#include <assert.h>
#include <string.h> 
#include "base64.h" 
#include "serialization.h" 
/*
 * SimpleSecureChat Serialization Library. Made with Security in mind.
*/

sscso *SSCS_object(){
	sscso* obj = malloc(sizeof(struct SSCS_struct));		
	obj->buf_ptr = NULL; obj->allocated = 0;
	return obj;
}

sscso *SSCS_open(byte* buf){
	size_t len = strlen((const char*)buf);
	byte* buf_ptr = malloc(len);
	memcpy(buf_ptr,buf,len);
	sscso* obj = malloc(sizeof(struct SSCS_struct));
	obj->buf_ptr = buf_ptr;
	obj->allocated = len;
	return obj;
}
int SSCS_object_add_data(sscso* obj,char* label,byte* data,size_t size){
	if(size <= 0)return -1; //Size has to be bigger than 0
	void *old_buf_ptr = obj->buf_ptr;
	size_t old_buf_size = obj->allocated;	
	size_t encoded_size;
	if(old_buf_ptr != NULL){
		byte* validationpointer = (byte*)strstr((const char*)old_buf_ptr,label);
		if(validationpointer != NULL){
			puts("Label Already Exists");	
			return -1;
		}
	}

	byte* b64data = base64_encode(data,size,&encoded_size);
	int b64datalen = encoded_size;
	int label_len = strlen((const char*)label);
	size_t final_intermediate_len = b64datalen+label_len+4;
	byte* intermediatebuf = malloc(final_intermediate_len);
	memset(intermediatebuf,0,final_intermediate_len);
	byte* ibufwloc = intermediatebuf; //ibufwloc is a pointer to the next area to write to
	int i = 0;
	while(i < label_len){
		*ibufwloc = label[i];
		ibufwloc++;
		i++;
	}
	*ibufwloc = ':';
	ibufwloc++;
	*ibufwloc = '"';
	ibufwloc++;
	memcpy(ibufwloc,b64data,encoded_size); //Add B64 encoded data 
	ibufwloc += b64datalen;
	*(ibufwloc) = '"';
	ibufwloc++;
	*ibufwloc = ';';
	ibufwloc++;
	free(b64data);	
	size_t new_buf_size = (old_buf_size + final_intermediate_len);
	void *new_buf_ptr = malloc(new_buf_size+1);
	memset(new_buf_ptr,0,new_buf_size);
	if(old_buf_ptr != NULL)memcpy(new_buf_ptr,old_buf_ptr,old_buf_size);
	free(old_buf_ptr);
	old_buf_ptr = NULL;
	i = 0;
	byte* base_ptr = new_buf_ptr + old_buf_size ;	
	while(i < (int)final_intermediate_len){
		*base_ptr = intermediatebuf[i];	
		base_ptr++;
		i++;
	}
	*(byte*)(new_buf_ptr+new_buf_size) = '\0';
	obj->allocated = new_buf_size;
	obj->buf_ptr = new_buf_ptr;
	free(intermediatebuf);
	return 0;
}
sscsd* SSCS_object_data(sscso* obj,char* label){
	byte* buf_ptr = obj->buf_ptr;
	size_t allocated = obj->allocated;
	size_t label_len = strlen((const char*)label);
	byte* readpointer = (byte*)strstr((const char*)buf_ptr,label);
	if(readpointer == NULL){
		puts("Label Not Found");
		return NULL;
	}
	readpointer+=label_len;
	if(readpointer[0] != ':' || readpointer[1] != '"'){
		puts("Label Error");
		return NULL;
	}
	readpointer+=2;
	//Readpointer is now at the beginning of the base64 encoded data
	int i = 0;
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Run once to get length of string 
		if(!((readpointer+i)-buf_ptr < (signed)allocated)){
			puts("Outsize of memory bounds");
			return NULL;
		}
		i++;	
	}
	double b64encoded_len = i; 
	byte* b64buffer = malloc(b64encoded_len+1); 
	i = 0;
	/* Run loop again to read encoded string */
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Get base64encoded data 
		if(!((size_t)((readpointer+i) - buf_ptr) < allocated) || b64encoded_len < i){
			puts("Outsize of memory bounds");
			free(b64buffer);
			return NULL;
		}
		*(b64buffer+i) = *(readpointer+i);	
		i++;
	}
	size_t len; 
	sscsd* final = malloc(sizeof(sscsd));
	final->data = base64_decode((const unsigned char*)b64buffer,b64encoded_len,&len); //NOTE THAT THIS IS A POINTER (if an integer was serialized an (int*) )
	final->len = len;
	free(b64buffer);
	return final;
}

char* SSCS_object_encoded(sscso* obj){ //Get string to send over socket
	return obj->buf_ptr;
}

size_t SSCS_object_encoded_size(sscso* obj){ //Get size of string(often needs to be specified when sending over socket)
	return obj->allocated;	
} 

byte* SSCS_data_get_data(sscsd* data){
	return data->data;
}

size_t SSCS_data_get_size(sscsd* data){
	return data->len;
}
void SSCS_free(sscso* obj){ //Frees current buffer associated with sscso obj (Object Can be Reused)
	free(obj->buf_ptr);
	obj->buf_ptr = NULL;
	obj->allocated = 0;
}

void SSCS_release(sscso** obj){ //Frees the current buffer AND the structure holding the address to the buffer; (Object Cant be Reused)
	free(((*obj)->buf_ptr));
	free(*obj);
	*obj = NULL;
}
void SSCS_data_release(sscsd** data){ //Frees the data buffer AND the structure holding the address and the length
	if(*data == NULL)return;
	free(((*data)->data));
	free(*data);
	*data = NULL;	
}
/*
* Wrappers for SSCS_object_data() to simplify usage 
*/
int SSCS_object_int(sscso* obj,char* label){
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return -1;
	if(data->len != sizeof(int)){
		puts("Data stored with label is not an integer");
		SSCS_data_release(&data);
		return -1;
	}
	int retval = *(int*)(data->data);
	SSCS_data_release(&data);
	return retval;
}
double SSCS_object_double(sscso* obj,char* label){
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return -1;
	if(data->len != sizeof(double)){
		puts("Data stored with label is not a double");
		SSCS_data_release(&data);
		return -1;
	}	
	double retval = *(int*)data->data;
	SSCS_data_release(&data);
	return retval;
}
unsigned char* SSCS_object_string(sscso* obj,char* label){
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return NULL;
	unsigned char* ret_ptr = malloc(data->len+2);
	memcpy(ret_ptr,data->data,data->len);
	*(ret_ptr+data->len + 1) = '\0';
	SSCS_data_release(&data);
	
	return ret_ptr;
	
}

