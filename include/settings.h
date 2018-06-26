
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
* This file contains all the configurable settings for SimpleSecureChat (Client)
*/

#ifndef SSC_SETTINGSHF
#define SSC_SETTINGSHF
#include <../config.h>
typedef unsigned char byte;

/* Uncomment below for debug information */
//#define DEBUG 

/* Comment out if you want to use your own server */
//#define _USE_DEFAULT_SERVER

#ifdef _USE_DEFAULT_SERVER
	#include "../default/default_server.h"
#else
	#define HOST_NAME "127.0.0.1"
	#define HOST_PORT "5050"
	#define HOST_CERT "public.pem"
#endif /* _USE_DEFAULT_SERVER */

#define PUB_KEY "rsapublickey.pem" //Public Key location (Will be generated if not found)
#define PRIV_KEY "rsaprivatekey.pem" //Private Key location (Will be generated if not found)
#define KEYSIZE 2048 //keysize used to generate key (has to be 1024,2048,4096,or 8192)

#define DB_FNAME "sscdb.db" //SQLITE Database Filename(Will be generated if not found)

/*
 * By default SSC spawns a seperate thread to get new messages from the server, to disable this 
 * feature comment out the line below (SSC_UPDATE_THREAD)
 * if not using a seperate thread, updates will be done by ssc_cli_msg_upd() (in headers/cli.c) 
 * at a set interval
 */
#define SSC_UPDATE_THREAD
#define SSC_UPDATE_INTERVAL 1000 //only applicable if using a seperate update thread

#endif
