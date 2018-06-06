
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
* All configurable settings for SSCServer
*/

/* Miscellaneous */
//#define DEBUG //uncomment for additional debug info
#define SSC_VERIFY_VARIABLES //sanity check variables 

/* Settings for MySQL/MariaDB */
#define SSCDB_SRV "localhost" //mysql server
#define SSCDB_USR "SSCServer" //mysql username
#define SSCDB_PASS "passphrase" //mysql password 

/* Log Settings */
#define SSCS_LOGTOFILE //Keep defined -> stdout&stderr goto SSCS_LOGFILE
#define SSCS_LOGFILE "SSCServer.log" //Logfile to write to 

/* Certificate file Settings */
#define SSCS_CERTFILE "cert.pem" //certificate file
#define SSCS_KEYFILE "key.pem" //Key file
#define SSCS_KEYFILE_PW "test" //key file password

/* 
 * Use Custom Malloc or system specific malloc & free
 * NOTE: The custom malloc has a HUGE ~4KB overhead per allocation due to a Guard Page protecting 
 * against Heap Overflows
 *
 * Better-performance -> Use Default Malloc 
 * Security -> Use Custom Malloc
 */

#define SSCS_CUSTOM_MALLOC /* comment out to use the system specific malloc & free */

#ifdef SSCS_CUSTOM_MALLOC
	#include "protected_malloc.h"
#else
	#define cmalloc(size) calloc(1,size) 
	#define cfree(ptr) free(ptr) 
	#define cmalloc_init() puts("") 
#endif

/*
 * How to handle each client:
 * forking (New process for each child -> More Secure)
 * threading (Same memory space, new stack -> Better Performance)
 */
//#define SSCS_CLIENT_FORK

#endif /* SSC_SETTINGSHFSRV */
