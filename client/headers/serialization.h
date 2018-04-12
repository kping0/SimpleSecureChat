#ifndef SSCS_SERIALIZATION
#define SSCS_SERIALIZATION

struct SSCS_struct{ //SSCS_object
	void* buf_ptr; //Pointer to current buffer
	size_t allocated; //Size of current buffer (allocated amount)
};

struct SSCS_data{ //Object returned by SSCS_object_data
	void* data; //Data returned by function
	size_t len; //Length of data
};

typedef struct SSCS_struct sscso; //SimpleSecureChatSerialized_Object
typedef struct SSCS_data sscsd; //SimpleSecureChatSerialized_Data

typedef unsigned char byte;

sscso *SSCS_object(void);

sscso *SSCS_open(byte* buf);

int SSCS_object_add_data(sscso* obj,char* label,byte* data,size_t size);

sscsd* SSCS_object_data(sscso* obj,char* label);

char* SSCS_object_encoded(sscso* obj);

size_t SSCS_object_encoded_size(sscso* obj);

byte* SSCS_data_get_data(sscsd* data);

size_t SSCS_data_get_size(sscsd* data);

void SSCS_free(sscso* obj);

void SSCS_release(sscso** obj);

void SSCS_data_release(sscsd** data);

int SSCS_object_int(sscso* obj,char* label);

double SSCS_object_double(sscso* obj,char* label);

unsigned char* SSCS_object_string(sscso* obj,char* label);

#endif /* SSCS_SERIALIZATION */

