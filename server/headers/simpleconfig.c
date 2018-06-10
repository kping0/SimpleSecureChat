#include "simpleconfig.h"

SCONFIG* sconfig_new_internal(const char* file,int line){
	SCONFIG* new_config = cmalloc(sizeof(SCONFIG));
	if(new_config == NULL){
		cexit("sconfig_new() could not allocate memory (file: %s - line: %d)",file,line);
	}
	new_config->configpath = NULL;
	new_config->configtemp = NULL;
	new_config->configchanged = 0;
	return new_config;
}
void sconfig_close_internal(SCONFIG** sconfig_object){
	if(sconfig_object == NULL)return;
	SCONFIG* obj = *sconfig_object;
	if(obj == NULL)return;
	if(obj->configpath != NULL)cfree(obj->configpath);
	if(obj->configtemp != NULL)SSCS_release(&(obj->configtemp));
	cfree(obj);
	sconfig_object = NULL;
	return;
}
int sconfig_check_internal(SCONFIG* obj,const char* file, int line){
	if(obj == NULL){
		cdebug("sconfig_check() passed SCONFIG object is NULL (file: %s - line: %d)",file,line);
		return -1;
	}
	if(obj->configpath == NULL){
		cdebug("sconfig_check() SCONFIG object->configpath is NULL (file: %s - line: %d)",file,line);
		return -1;
	}
	if(obj->configtemp == NULL){
		cdebug("sconfig_check() SCONFIG object->configtemp is NULL (file: %s - line: %d)",file,line);
		return -1;
	}
	cdebug("sconfig_check() check completed with no errors.");
	return 0;
}

SCONFIG* sconfig_load_internal(byte* path_to_config,const char* file,int line){
	if(path_to_config == NULL)return NULL;
	SCONFIG* obj = sconfig_new_internal(file,line);

	size_t path_to_config_len = strlen(path_to_config) + 1;
	byte* path_to_config_cpy = cmalloc(path_to_config_len);		
	if(path_to_config_cpy == NULL){
		cfree(obj);
		cexit("sconfig_load() could not allocate memory (file: %s - line: %d)",file,line);
	}
	memcpy(path_to_config_cpy,path_to_config,path_to_config_len);
	obj->configpath = path_to_config_cpy;

	FILE* configfile = fopen(path_to_config_cpy,"rb");
	if(configfile == NULL){
		cinfo("sconfig_load() could not open the path specified (%s), trying to create file... ",path_to_config_cpy);	
		configfile = fopen(path_to_config_cpy,"wb+");
		if(!configfile){
			sconfig_close_internal(&obj);
			cexit("sconfig_load() could not create the path specified (%s) (file: %s - line: %d)",path_to_config,file,line);
		}
	}
	fseek(configfile,0,SEEK_END);
	long config_length = ftell(configfile);
	fseek(configfile,0,SEEK_SET);

	byte* configtemp_buf = cmalloc(config_length + 1);
	if(configtemp_buf){
		fread(configtemp_buf,1,config_length,configfile);
		obj->configtemp = SSCS_open(configtemp_buf);
		cfree(configtemp_buf);
		fclose(configfile);
		return obj;
	}
	else{
		cfree(obj);
		fclose(configfile);
		cexit("[SimpleConfig] could not allocate memory for configtemp");
		return NULL;
	}
}

void* sconfig_get_internal(SCONFIG* obj,byte* object_name,const char* file, int line){
	if(sconfig_check_internal(obj,file,line) != 0)return NULL;
	sscsd* data = SSCS_object_data(obj->configtemp,object_name);				
	if(data == NULL)return NULL;
	byte* retptr = data->data;	
	cfree(data);	/* free structure, but not buffer */
	return retptr; /* user is responsible for cfree() */
}

int sconfig_set_internal(SCONFIG* obj,char* label,byte* data,size_t len,const char* file,int line){
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	return SSCS_object_add_data(obj->configtemp,label,data,len); //if -1, label exits
}
int sconfig_unset_internal(SCONFIG* obj,char* label,const char* file,int line){
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	return SSCS_object_remove_data(obj->configtemp,label);
}
int sconfig_write_internal(SCONFIG* obj,const char* file, int line){
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	FILE* configfile = fopen(obj->configpath,"wb");	 //start overwriting current config
	char* config_new = SSCS_object_encoded(obj->configtemp);
	if(config_new == NULL){
		fclose(configfile);
		return -1;
	}
	fprintf(configfile,"%s",config_new);
	fflush(configfile);
	fclose(configfile);
	cfree(config_new);
	return 0;
}
