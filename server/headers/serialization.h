#ifndef SSCS_SERIALIZATION
#define SSCS_SERIALIZATION

#include "settings.h"

struct SSCS_struct{ //SSCS_object
	void* buf_ptr; //Pointer to current buffer
	size_t allocated; //Size of current buffer (allocated amount)
};

struct SSCS_data{ //Object returned by SSCS_object_data
	void* data; //Data returned by function
	size_t len; //Length of data
};
struct SSCS_list{
	void* buf_ptr; //Pointer to current buffer
	size_t allocated; //Size of current buffer
	size_t items; //items in buf_ptr;
	size_t readloc; //used when reading from the list
};

typedef struct SSCS_struct sscso; //SimpleSecureChatSerialized_Object

typedef struct SSCS_data sscsd; //SimpleSecureChatSerialized_Data

typedef struct SSCS_list sscsl; //SimpleSecureChatSerialized_List

typedef unsigned char byte;


byte* memseq(byte* buf,size_t buf_size,byte* byteseq,size_t byteseq_len); //Search memory buf with sizeof buf_size for byte sequence byteseq with sizeof byteseq_len and return ptr to first occurence
	
sscso *SSCS_object(void); //Generate SSCS_object

sscsl *SSCS_list(void); //Generate SSCS_list

sscso *SSCS_open(byte* buf); //Open an encoded sscs object

sscsl *SSCS_list_open(byte* buf); //open an encoded list

int SSCS_object_add_data(sscso* obj,char* label,byte* data,size_t size); //adds data to a SSCS_object 

sscsd* SSCS_object_data(sscso* obj,char* label); //returns SSCS_data struct that has to be freed using SSCS_data_release(&data_structure)

int SSCS_list_add_data(sscsl* list,byte* data,size_t size); //add data to list 

sscsd* SSCS_list_data(sscsl* list,unsigned int index); //get data from list with an index of i (i < 4096)

char* SSCS_object_encoded(sscso* obj); //get encoded version of SSCS_object

size_t SSCS_object_encoded_size(sscso* obj); //get size of sscs_encoded object

char* SSCS_list_encoded(sscsl* list); //get encoded version of SSCS_list

size_t SSCS_list_encoded_size(sscsl* list); //get size of sscs encoded list

byte* SSCS_data_get_data(sscsd* data); //equivalent of doing : ... setup sscsd* data_obj...; data_obj->data

size_t SSCS_data_get_size(sscsd* data); //data_obj->len

//void SSCS_free(sscso* obj); //Useless

void SSCS_release(sscso** obj); //release associated pointers and struct itself (has to be passed a reference eg. SSCS_release(&obj) 

void SSCS_data_release(sscsd** data); //release associated pointers and struct itself SSCS_data_release(&data)

void SSCS_list_release(sscsl** list); //s.o SSCS_list_release(&list)

int SSCS_object_int(sscso* obj,char* label); //wrapper around SSCS_object_data

double SSCS_object_double(sscso* obj,char* label); //wrapper around SSCS_object_data

unsigned char* SSCS_object_string(sscso* obj,char* label); //wrapper around SSCS_object_data

#endif /* SSCS_SERIALIZATION */

