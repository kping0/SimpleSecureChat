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
byte* memseq(byte* buf,size_t buf_size,byte* byteseq,size_t byteseq_len){ 
	debugprint();
	size_t i = 0;size_t x = 0;byte* firstbyte = NULL; //Initialize variables
	while(1){
		if(!(i < buf_size))return NULL;
		if(buf[i] == byteseq[x]){
			firstbyte = (buf+i); //Pointer to be returned if we find the seq
			x++;i++;
			while(1){	
				if(x == byteseq_len)return firstbyte; //we found the byte sequence
				else if(!(i < buf_size))return NULL; //exit,have reached buf_size
				else if(buf[i] == byteseq[x]){x++;i++;} //match,continue
				else{x = 0;firstbyte = NULL;break;} //byte's didnt match,reset
			}		
		}	
		else{i++;} //If byte's dont match add increase the index 
	}	
	return NULL;
}
sscso *SSCS_object(void){
	debugprint();
	sscso* obj = cmalloc(sizeof(struct SSCS_struct));		
	obj->buf_ptr = NULL; 
	obj->allocated = 0;
	return obj;
}
sscsl *SSCS_list(void){
	debugprint();
	sscsl* list = cmalloc(sizeof(struct SSCS_list));
	list->buf_ptr = NULL;
	list->allocated = 0;
	list->items = 0;
	list->readloc = 0;
	return list;
}
sscsl *SSCS_list_open(byte* buf){
	debugprint();
	size_t len = strlen((const char*)buf);
	void* buf_ptr = cmalloc(len);
	memcpy(buf_ptr,buf,len);
	sscsl *list = cmalloc(sizeof(struct SSCS_list));
	list->buf_ptr = buf_ptr;
	list->allocated = len;
	return list;
}

sscso *SSCS_open(byte* buf){
	debugprint();
	size_t len = strlen((const char*)buf);
	void* buf_ptr = cmalloc(len);
	memcpy(buf_ptr,buf,len);
	sscso* obj = cmalloc(sizeof(struct SSCS_struct));
	obj->buf_ptr = buf_ptr;
	obj->allocated = len;
	return obj;
}
int SSCS_list_add_data(sscsl* list,byte* data,size_t size){
	debugprint();
	if(size <= 0)return -1; //Size has to be bigger than 0
	void *old_buf_ptr = list->buf_ptr;
	size_t old_buf_size = list->allocated;	
	size_t old_buf_items = list->items;
	size_t encoded_size;
	byte* b64data = mitbase64_encode(data,size,&encoded_size);
	int b64datalen = encoded_size;
	if(old_buf_items >= 100000)return -1; //If more than 100K items exists exit
	byte label[12];
	sprintf(label,"%zd:\"",old_buf_items+1);
	int label_len = strlen((const char*)label);
	size_t final_intermediate_len = b64datalen+label_len+2;
	byte* intermediatebuf = cmalloc(final_intermediate_len);
	memset(intermediatebuf,0,final_intermediate_len);
	byte* ibufwloc = intermediatebuf; //ibufwloc is a pointer to the next area to write to
	int i = 0;
	while(i < label_len){
		*ibufwloc = label[i];
		ibufwloc++;
		i++;
	}
	memcpy(ibufwloc,b64data,encoded_size); //Add B64 encoded data 
	ibufwloc += b64datalen;
	*(ibufwloc) = '"';
	ibufwloc++;
	*ibufwloc = ';';
	ibufwloc++;
	cfree(b64data);	
	size_t new_buf_size = (old_buf_size + final_intermediate_len);
	void *new_buf_ptr = cmalloc(new_buf_size);
	memset(new_buf_ptr,0,new_buf_size);
	if(old_buf_ptr != NULL)memcpy(new_buf_ptr,old_buf_ptr,old_buf_size);
	cfree(old_buf_ptr);
	old_buf_ptr = NULL;
	i = 0;
	byte* base_ptr = new_buf_ptr + old_buf_size ;	
	while(i < (int)final_intermediate_len){
		*base_ptr = intermediatebuf[i];	
		base_ptr++;
		i++;
	}
	list->allocated = new_buf_size;
	list->buf_ptr = new_buf_ptr;
	list->items = old_buf_items+1;
	cfree(intermediatebuf);
	return 0;
}
int SSCS_object_add_data(sscso* obj,byte* label,byte* data,size_t size){
	debugprint();
	if(size <= 0)return -1; //Size has to be bigger than 0
	void *old_buf_ptr = obj->buf_ptr;
	size_t old_buf_size = obj->allocated;	
	int label_len = (int)strlen((const char*)label);
	int modlabel_len = label_len+2;
	byte* modlabel = cmalloc(modlabel_len+1); //+1 for the NUL 
	sprintf(modlabel,"%s:\"",label);
	size_t encoded_size;
	if(old_buf_ptr != NULL){
		byte* validationpointer = memseq((byte*)old_buf_ptr,old_buf_size,(byte*)modlabel,modlabel_len);
		if(validationpointer != NULL){
			cfree(modlabel);
			cinfo("label '%s' already exists",label);
			return -1;
		}
	}

	byte* b64data = mitbase64_encode(data,size,&encoded_size);
	int b64datalen = encoded_size;
	size_t final_intermediate_len = b64datalen+modlabel_len+2; //+2 for the ' "; ' at the end
	byte* intermediatebuf = cmalloc(final_intermediate_len);
	byte* ibufwloc = intermediatebuf; //ibufwloc is a pointer to the next area to write to
	size_t i = 0;
	while(i < strlen(modlabel)){
		*ibufwloc = modlabel[i];
		ibufwloc++;
		i++;
	}
	memcpy(ibufwloc,b64data,encoded_size); //Add B64 encoded data 
	ibufwloc += b64datalen;
	*(ibufwloc) = '"';
	ibufwloc++;
	*ibufwloc = ';';
	ibufwloc++;
	cfree(b64data);	
	size_t new_buf_size = (old_buf_size + final_intermediate_len);
	void *new_buf_ptr = cmalloc(new_buf_size);
	memset(new_buf_ptr,0,new_buf_size);
	if(old_buf_ptr != NULL){
		memcpy(new_buf_ptr,old_buf_ptr,old_buf_size);
		cfree(old_buf_ptr);
	}
	old_buf_ptr = NULL;
	i = 0;
	byte* base_ptr = new_buf_ptr + old_buf_size ;	
	while(i < final_intermediate_len){
		*base_ptr = intermediatebuf[i];	
		base_ptr++;
		i++;
	}
	obj->allocated = new_buf_size;
	obj->buf_ptr = new_buf_ptr;
	cfree(intermediatebuf);
	cfree(modlabel);
	return 0;
}
int SSCS_object_remove_data(sscso* obj,byte* label){
	debugprint();
	if(!label)return -1;
	byte *buf_ptr = obj->buf_ptr;
	if(!buf_ptr)return -1;
	size_t buf_size = obj->allocated;	
	size_t label_len = strlen((const char*)label);
	size_t modlabel_len = label_len+2;
	byte modlabel[modlabel_len+1];
	sprintf(modlabel,"%s:\"",label);
	byte* label_data = memseq(buf_ptr,buf_size,(byte*)modlabel,modlabel_len);
	if(!label_data){
		cinfo("There is no data associated with the label '%s'",label);
		return -1;
	}
	byte* wptr = label_data + modlabel_len; //start of b64data
	size_t count_iteration = 0;
	while(wptr[count_iteration] != '"' && wptr[count_iteration+1] != ';'){ //Run once to get length of string 
		if(!((wptr+count_iteration)-buf_ptr < (signed)buf_size)){
			cerror("out of bounds loop");
			cfree(modlabel);
			return -1;	
		}
		count_iteration++;	
	}
	count_iteration+=2; //for the ' "; ' at the end
	memset(label_data,'0',count_iteration+modlabel_len);		
	size_t buf_ptr_to_label_data = label_data - buf_ptr;
	cdebug("calculated buf_ptr_to_label_data %d",buf_ptr_to_label_data);
	size_t after_data_to_allocated = buf_size - buf_ptr_to_label_data - /* following is the actual removed block */ count_iteration - modlabel_len; //bytes after removed block
	cdebug("calculated label_data_to_allocated %d",after_data_to_allocated);
	memmove(label_data,label_data+count_iteration+modlabel_len,after_data_to_allocated);
	size_t buffer_size_after_remove = buf_ptr_to_label_data+after_data_to_allocated;
	cdebug("final buffer after remove is %d",buffer_size_after_remove);
	byte* new_buf_ptr = cmalloc(buffer_size_after_remove);
	memcpy(new_buf_ptr,buf_ptr,buffer_size_after_remove);
	cfree(buf_ptr);
	obj->buf_ptr = new_buf_ptr;
	obj->allocated = buffer_size_after_remove;
	return 0;
}
sscsd* SSCS_object_data(sscso* obj,byte* label){
	debugprint();
	byte* buf_ptr = obj->buf_ptr;
	size_t allocated = obj->allocated;
	size_t label_len = strlen((const char*)label);
	size_t modlabel_len = label_len+2;
	byte modlabel[modlabel_len+1];
	sprintf(modlabel,"%s:\"",label);	
	byte* readpointer = memseq(buf_ptr,allocated,modlabel,modlabel_len);
	if(!readpointer)return NULL;
	readpointer+=modlabel_len;
	//Readpointer is now at the beginning of the base64 encoded data
	int i = 0;
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Run once to get length of string 
		if(!((readpointer+i)-buf_ptr < (signed)allocated))return NULL;
		i++;	
	}
	double b64encoded_len = i; 
	byte* b64buffer = cmalloc(b64encoded_len+1); 
	i = 0;
	/* Run loop again to read encoded string */
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Get base64encoded data 
		if(!((size_t)((readpointer+i) - buf_ptr) < allocated) || b64encoded_len < i){
			cfree(b64buffer);
			return NULL;
		}
		*(b64buffer+i) = *(readpointer+i);	
		i++;
	}
	size_t len; 
	sscsd* final = cmalloc(sizeof(sscsd));
	final->data = mitbase64_decode((const unsigned char*)b64buffer,b64encoded_len,&len); //NOTE THAT THIS IS A POINTER (if an integer was serialized an (int*) )
	final->len = len;
	cfree(b64buffer);
	return final;
}
sscsd* SSCS_list_data(sscsl* list,unsigned int index){ //Auto incriments after every run.
	debugprint();
	if(index > 4096)return NULL; //support a max of 4096 items
	byte* buf_ptr = list->buf_ptr;
	size_t allocated = list->allocated;
	byte* label = cmalloc(30);
	sprintf(label,"%d:\"",index);
	size_t label_len = strlen((const char*)label);
	int i = 0;
	byte* readpointer = memseq(buf_ptr,allocated,(byte*)label,label_len);
	if(readpointer == NULL){
		return NULL;
	}
	readpointer+=label_len;
	//Readpointer is now at the beginning of the base64 encoded data
	i = 0;
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Run once to get length of string 
		if(!((readpointer+i)-buf_ptr < (signed)allocated)){
			//puts("Outsize of memory bounds");
			return NULL;
		}
		i++;	
	}
	double b64encoded_len = i; 
	byte* b64buffer = cmalloc(b64encoded_len+1); 
	i = 0;
	/* Run loop again to read encoded string */
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Get base64encoded data 
		if(!((size_t)((readpointer+i) - buf_ptr) < allocated) || b64encoded_len < i){
			//puts("Outsize of memory bounds");
			cfree(b64buffer);
			return NULL;
		}
		*(b64buffer+i) = *(readpointer+i);	
		i++;
	}
	size_t len; 
	sscsd* final = cmalloc(sizeof(sscsd));
	final->data = mitbase64_decode((const unsigned char*)b64buffer,b64encoded_len,&len); //NOTE THAT THIS IS A POINTER (if an integer was serialized an (int*) )
	final->len = len;
	cfree(b64buffer);
	cfree(label);
	return final;
}
byte* SSCS_object_encoded(sscso* obj){ //Get string to send over socket
	debugprint();
	byte* retptr = cmalloc(obj->allocated+2);
	memcpy(retptr,obj->buf_ptr,obj->allocated);
	*(retptr+obj->allocated+1) = '\0';	
	return retptr;
}

size_t SSCS_object_encoded_size(sscso* obj){ //Get size of string(often needs to be specified when sending over socket)
	debugprint();
	return obj->allocated;	
} 
byte* SSCS_list_encoded(sscsl* list){
	debugprint();
	byte* retptr = cmalloc(list->allocated+1);
	memcpy(retptr,list->buf_ptr,list->allocated);
	*(retptr+list->allocated) = '\0';
	return retptr;
}
size_t SSCS_list_encoded_size(sscsl* list){
	debugprint();
	return list->allocated;
}

byte* SSCS_data_get_data(sscsd* data){
	debugprint();
	return data->data;
}

size_t SSCS_data_get_size(sscsd* data){
	debugprint();
	return data->len;
}
/* UNUSED because all functions allocated a new sscso object and dont reuse 
void SSCS_free(sscso* obj){ //Frees current buffer associated with sscso obj (Object Can be Reused)
	cfree(obj->buf_ptr);
	obj->buf_ptr = NULL;
	obj->allocated = 0;
}
*/

void SSCS_release(sscso** obj){ //Frees the current buffer AND the structure holding the address to the buffer; (Object Cant be Reused)
	debugprint();
	cfree(((*obj)->buf_ptr));
	cfree(*obj);
	*obj = NULL;
}
void SSCS_data_release(sscsd** data){ //Frees the data buffer AND the structure holding the address and the length
	debugprint();
	if(*data == NULL)return;
	cfree(((*data)->data));
	cfree(*data);
	*data = NULL;	
}
void SSCS_list_release(sscsl** list){
	debugprint();
	if(*list == NULL)return;
	if((*list)->buf_ptr != NULL)cfree(((*list)->buf_ptr));
	cfree(*list);
	*list = NULL;
}
/*
* Wrappers for SSCS_object_data() to simplify usage 
*/
int SSCS_object_int(sscso* obj,byte* label){
	debugprint();
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return -1;
	if(data->len != sizeof(int)){
		//puts("Data stored with label is not an integer");
		SSCS_data_release(&data);
		return -1;
	}
	int retval = *(int*)(data->data);
	SSCS_data_release(&data);
	return retval;
}
double SSCS_object_double(sscso* obj,byte* label){
	debugprint();
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return -1;
	if(data->len != sizeof(double)){
		//puts("Data stored with label is not a double");
		SSCS_data_release(&data);
		return -1;
	}	
	double retval = *(int*)data->data;
	SSCS_data_release(&data);
	return retval;
}
unsigned char* SSCS_object_string(sscso* obj,byte* label){
	debugprint();
	sscsd* data = SSCS_object_data(obj,label);
	if(data == NULL)return NULL;
	unsigned char* ret_ptr = cmalloc(data->len+2);
	memcpy(ret_ptr,data->data,data->len);
	*(ret_ptr+data->len + 1) = '\0';
	SSCS_data_release(&data);
	
	return ret_ptr;
	
}

