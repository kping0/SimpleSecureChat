
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

#ifndef SSC_SETTINGSHF
#define SSC_SETTINGSHF

/*
* This file contains all the configurable settings for SimpleSecureChat (Client)
*/

//You can only have a GUI or a CLI, not both.. if both are defined SSC will not work
#define SSC_GUI /* To have a Gtk+ GUI */
//#define SSC_CLI
/*
 * Uncomment below for debug information
 */
//#define DEBUG 

/*
 * Default Server Configuration (Will use the default Server)
 * To change the Server change the HOST_NAME & HOST_CERT to match your servers
 */

#define HOST_NAME "52.14.103.245" //Default Server IP
#define HOST_PORT "5050" //SSC Port
#define HOST_CERT "default/public.pem" //Default Server Certificate (Change path if your hosting your own server)

#define PUB_KEY "rsapublickey.pem" //Public Key location (Will be generated if not found)
#define PRIV_KEY "rsaprivatekey.pem" //Private Key location (Will be generated if not found)
#define KEYSIZE 2048 //keysize used to generate key (has to be 1024,2048,4096,or 8192)

#define DB_FNAME "sscdb.db" //SQLITE Database Filename(Will be generated if not found)
#define SSC_VERIFY_VARIABLES //error check variables

#endif
