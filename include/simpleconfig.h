
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

#ifndef _SIMPLECONFIG_H
#define _SIMPLECONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "serialization.h"
#include "cstdinfo.h"

typedef unsigned char byte;

typedef struct{
	byte* configpath;
	sscso* configtemp;
	int configchanged;
	volatile sig_atomic_t lock;
} SCONFIG;

#define sconfig_new() sconfig_new_internal(__FILE__,__LINE__)
#define sconfig_close(x) sconfig_close_internal(&x) 
#define sconfig_load(x) sconfig_load_internal(x,__FILE__,__LINE__)
#define sconfig_check(x) sconfig_check_internal(x,__FILE__,__LINE__)
#define sconfig_get(x,y) sconfig_get_internal(x,y,__FILE__,__LINE__)
#define sconfig_set(x,y,a,b) sconfig_set_internal(x,y,a,b,__FILE__,__LINE__)
#define sconfig_unset(x,y) sconfig_unset_internal(x,y,__FILE__,__LINE__)
#define sconfig_write(x) sconfig_write_internal(x,__FILE__,__LINE__)
#define sconfig_set_str(x,y,z) sconfig_set_str_internal(x,y,z,__FILE__,__LINE__)
#define sconfig_set_int(x,y,z) sconfig_set_int_internal(x,y,z,__FILE__,__LINE__)
#define sconfig_get_full(x,y) sconfig_get_full_internal(x,y,__FILE__,__LINE__)
#define sconfig_get_str(x,y) sconfig_get_str_internal(x,y,__FILE__,__LINE__)
#define sconfig_get_int(x,y) sconfig_get_int_internal(x,y,__FILE__,__LINE__)

SCONFIG* sconfig_new_internal(const char* file, int line);

void sconfig_close_internal(SCONFIG** sconfig_object);

SCONFIG* sconfig_load_internal(byte* path_to_config,const char* file,int line);

int sconfig_check_internal(SCONFIG* obj, const char* file, int line);

void* sconfig_get_internal(SCONFIG* obj,byte* object_name,const char* file, int line); //note that this returns a POINTER, so if you stored an integer, you will get an int*, not an int

int sconfig_set_internal(SCONFIG* obj,char* label,byte* data,size_t len,const char* file,int line);

int sconfig_unset_internal(SCONFIG* obj,char* label,const char* file,int line);

int sconfig_write_internal(SCONFIG* obj,const char* file, int line);

int sconfig_config_exists(byte* path_to_config);
	
sscsd* sconfig_get_full_internal(SCONFIG* obj,byte* object_name,const char* file,int line);

byte* sconfig_get_str_internal(SCONFIG* obj,byte* label,const char* file,int line);

int sconfig_get_int_internal(SCONFIG* obj,char* label,const char* file,int line);
	
int sconfig_set_str_internal(SCONFIG* obj,char* label,byte* string_to_set,const char* file,int line);

int sconfig_set_int_internal(SCONFIG* obj,char* label,int integer_to_store,const char* file,int line);

#endif /* _SIMPLECONFIG_H */
