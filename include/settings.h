
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
* This file contains all the compile settings for SimpleSecureChat (Client)
*/

#ifndef SSC_SETTINGSHF
#define SSC_SETTINGSHF
#include <../config.h>
typedef unsigned char byte;





/* DO NOT EDIT ABOVE THIS LINE */
/* DO NOT EDIT ABOVE THIS LINE */
/* DO NOT EDIT ABOVE THIS LINE */


/* should only be defined in release ready code (&must be defined if compiling for a live enviroment) (cannot be defined with DEBUG) */
	// #define RELEASE_IMAGE 

/* Print debug information (cannot be defined on a release) */
	// #define DEBUG 

/* Spawn seperate update thread (to get messages from the server) */
	 #define SSC_UPDATE_THREAD

/* Interval for update thread in ms (if using an update thread) */
	 #define SSC_UPDATE_INTERVAL 500

/* Compile with GUI code (so you can choose between cli&gui) */
	 #define SSC_GUI

/* placeholder for unallowed characters */
	#define UNALLOWED_CHAR_PLACEHOLDER '~'

/* if you want raw unfiltered message output, otherwise only subset of ASCII */
	// #define RAW_MESSAGE_OUTPUT

/* log EVERY function call (DEBUG) */
	// #define SSC_FUNCTION_LOG


/* DO NOT EDIT BELOW THIS LINE */
/* DO NOT EDIT BELOW THIS LINE */
/* DO NOT EDIT BELOW THIS LINE */





#define DEFAULT_HOST_NAME "52.14.103.245" /* default server ip */

/* some macros for compatibility */
#define cmalloc(x) calloc(1,x)
#define cfree(x) free(x)
#define mitbase64_decode(x,y,z) base64_decode(x,y,z)
#define mitbase64_encode(x,y,z) base64_encode(x,y,z)

#if defined(DEBUG) && defined(RELEASE_IMAGE) 
	#error You cannot have debug enabled in a release build. 
#endif /* DEBUG && RELEASE_IMAGE */

#if defined(DEBUG) && defined(SSC_FUNCTION_LOG)
	#define debuginfo() cfunction_info()
	#define debugprint() cfunction_info()
#else
	#define debuginfo() cempty_function()
	#define debugprint() cempty_function()
#endif /* DEBUG && SSC_FUNCTION_LOG */

#endif
