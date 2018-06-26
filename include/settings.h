
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



/* Uncomment below for debug information */
/* #define DEBUG// */

/*
 * By default SSC spawns a seperate thread to get new messages from the server, to disable this 
 * feature comment out the line below (SSC_UPDATE_THREAD)
 */
#define SSC_UPDATE_THREAD
#define SSC_UPDATE_INTERVAL 1000 /* if using update thread, time between updates in ms */

/* Do you want to have the option to use the gui ? (comment out if you do NOT) */
#define SSC_GUI


/* DO NOT EDIT BELOW THIS LINE */
/* DO NOT EDIT BELOW THIS LINE */
/* DO NOT EDIT BELOW THIS LINE */

#define DEFAULT_HOST_NAME "52.14.103.245" /* default server ip */
/* #define RELEASE_IMAGE// */

/* some macros for compatibility */
#define cmalloc(x) calloc(1,x)
#define cfree(x) free(x)
#define mitbase64_decode(x,y,z) base64_decode(x,y,z)
#define mitbase64_encode(x,y,z) base64_encode(x,y,z)

#endif
