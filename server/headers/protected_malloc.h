
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


/*
 *  Memory Layout for structures on heap allocated by these functions
 *
 * -------------------------------------------------------------------------------------------------
 * | MAGIC | CHKVAR | SIZEOF_BUFFER | 0x0 | USABLE_BUFFER | 0x0 | CHKVAR | MAGIC | ... | GUARDPAGE |
 * -------------------------------------------------------------------------------------------------
 * |  4B   |   8B   |      8B       |  1B | 	VAR       | 1B  |   8B   |  4B   | VAR |   4096B   | 
 * -------------------------------------------------------------------------------------------------
 * 
 */

#ifndef SSCS_PROTECTED_MEMALLOC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "settings.h"


#ifndef PAGESIZE /* Usually defined in limits.h */
#define PAGESIZE 4096
#endif 

#define SSCS_HEAP_MAGIC 0x73736373 /* MAGIC */

typedef unsigned char byte;

#ifdef SSCS_CUSTOM_MALLOC

/* Macros for functions */
#define cmalloc(size) sscs_cmalloc(size,__FILE__,__LINE__) //call cmalloc(size)
#define cfree(ptr) sscs_cfree(ptr,__FILE__,__LINE__) //call cfree(ptr)
#define chkaddr(ptr) sscs_chkaddr(ptr,__FILE__,__LINE__) //call chkaddr(ptr)
#define cmalloc_init() sscs_cmalloc_init() //call cmalloc_init()
#define objsize(ptr) sscs_heap_object_size(ptr,__FILE__,__LINE__) //call objsize(ptr)


void sscs_cmalloc_init(void); //call once to init rng 

void sscs_cfree(void* ptr,const char* file,int line); //free for sscs_cmalloc  
	
void sscs_chkaddr(void* ptr,const char* file,int line); //check address for overflows and padding issues & errors

void* sscs_cmalloc(size_t size,const char* file,int line); //malloc wrapper with error checking

size_t sscs_heap_object_size(void* ptr,const char* file,int line);

#endif /* SSCS_CUSTOM_MALLOC */
#endif /* SSCS_PROTECTED_MEMALLOC */
