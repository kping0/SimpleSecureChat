
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

#include "simpleconfig.h"

static int nsleep(long miliseconds){ //Thread Safe Sleep
	debugprint();
   struct timespec req, rem;
   if(miliseconds > 999){   
        req.tv_sec = (int)(miliseconds / 1000);                           
        req.tv_nsec = (miliseconds - ((long)req.tv_sec * 1000)) * 1000000;
   }   
   else{   
        req.tv_sec = 0;                      
        req.tv_nsec = miliseconds * 1000000;
   }   

   return nanosleep(&req , &rem);
}


SCONFIG* sconfig_new_internal(const char* file,int line){
	debugprint();
	SCONFIG* new_config = cmalloc(sizeof(SCONFIG));
	if(new_config == NULL){
		cexit("sconfig_new() could not allocate memory (file: %s - line: %d)",file,line);
	}
	new_config->configpath = NULL;
	new_config->configtemp = NULL;
	new_config->configchanged = 0;
	new_config->lock = 0;
	return new_config;
}
void sconfig_close_internal(SCONFIG** sconfig_object){
	debugprint();
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
	debugprint();
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

int sconfig_config_exists(byte* path_to_config){
	debugprint();
	if(path_to_config == NULL)return -1;
	FILE* testfd = fopen(path_to_config,"rb");		
	if(testfd == NULL)return 0;
	fclose(testfd);	
	return 1;
}

SCONFIG* sconfig_load_internal(byte* path_to_config,const char* file,int line){
	debugprint();
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
	debugprint();
	if(sconfig_check_internal(obj,file,line) != 0)return NULL;
	sscsd* data = SSCS_object_data(obj->configtemp,object_name);				
	if(data == NULL)return NULL;
	byte* retptr = data->data;	
	cfree(data);	/* free structure, but not buffer */
	return retptr; /* user is responsible for cfree() */
}
sscsd* sconfig_get_full_internal(SCONFIG* obj,byte* object_name,const char* file,int line){
	debugprint();
	if(sconfig_check_internal(obj,file,line) != 0)return NULL;
	sscsd* data = SSCS_object_data(obj->configtemp,object_name);				
	if(data == NULL)return NULL;
	return data; /* free data using SSCS_data_release(&data) */
}
byte* sconfig_get_str_internal(SCONFIG* obj,byte* label,const char* file,int line){
	return sconfig_get_internal(obj,label,file,line);	
}
int sconfig_get_int_internal(SCONFIG* obj,char* label,const char* file,int line){
	debugprint();
	sscsd* data = sconfig_get_full_internal(obj,label,file,line);
	if(data == NULL){
		cerror("sconfig_get_int() could not retrieve data for label '%s'",label);
		SSCS_data_release(&data);
		return -1;
	}
	if(data->len != sizeof(int)){
		cerror("sconfig_get_int() object is not of length int");	
		SSCS_data_release(&data);
		return -1;
	}
	int retval = *(int*)(data->data);
	SSCS_data_release(&data);
	return retval;	
}
int sconfig_set_internal(SCONFIG* obj,char* label,byte* data,size_t len,const char* file,int line){
	debugprint();
	while(obj->lock == 1){
		nsleep(50);
	}
	obj->lock = 1;
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	int rv = SSCS_object_add_data(obj->configtemp,label,data,len); //if -1, label exits
	obj->lock = 0;
	return rv;
}
int sconfig_set_str_internal(SCONFIG* obj,char* label,byte* string_to_set,const char* file,int line){
	debugprint();
	size_t len = strlen(string_to_set);
	return sconfig_set_internal(obj,label,string_to_set,len,file,line);		
}
int sconfig_set_int_internal(SCONFIG* obj,char* label,int integer_to_store,const char* file,int line){
	debugprint();
	size_t len = sizeof(int);
	return sconfig_set_internal(obj,label,(byte*)&integer_to_store,len,file,line);
}
int sconfig_unset_internal(SCONFIG* obj,char* label,const char* file,int line){
	debugprint();
	while(obj->lock == 1){
		nsleep(50);
	}	
	obj->lock = 1;
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	int rv = SSCS_object_remove_data(obj->configtemp,label);
	obj->lock = 0;
	return rv;		
}
int sconfig_write_internal(SCONFIG* obj,const char* file, int line){
	debugprint();
	if(sconfig_check_internal(obj,file,line) != 0)return -1;
	while(obj->lock == 1){
		nsleep(50);
	}
	obj->lock = 1;
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
	obj->lock = 0;
	return 0;
}
