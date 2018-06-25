
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

#ifndef SSC_SETTINGSHFSRV
#define SSC_SETTINGSHFSRV

/*
 * Settings for SSCServer (compile settings, cannot be changed at runtime)
 */

//#define DEBUG /* print debug information (ALOT!) */

//#define SSCS_CLIENT_FORK /* uncomment if you want to have SSCS fork() for every client */

#define SSCS_CUSTOM_MALLOC /* comment out to use the system specific malloc & free */


/* DO NOT EDIT BEYOND THIS LINE */
/* DO NOT EDIT BEYOND THIS LINE */
/* DO NOT EDIT BEYOND THIS LINE */

#ifdef SSCS_CUSTOM_MALLOC
	#include "protected_malloc.h"
#else
	#define cmalloc(size) calloc(1,size) 
	#define cfree(ptr) free(ptr) 
	#define cmalloc_init() puts("") 
#endif

#endif /* SSC_SETTINGSHFSRV */
