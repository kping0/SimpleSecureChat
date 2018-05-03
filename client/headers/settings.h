
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
* This file contains all the configurable settings for SimpleSecureChat
*/

//You can only have a GUI or a CLI, not both.. if both are defined SSC will not work
#define SSC_GUI /* To have a Gtk+ GUI */
//#define SSC_CLI /* Uncomment for CLI version */
//#define DEBUG

#define HOST_NAME "127.0.0.1" //SSC Server IP
#define HOST_PORT "5050" //SSC Server Port
#define HOST_CERT "public.pem" //SSC Server public certificate (X509 Public Cert)

#define PUB_KEY "rsapublickey.pem" //Public Key location (Will be generated if not found)
#define PRIV_KEY "rsaprivatekey.pem" //Private Key location (Will be generated if not found)
#define KEYSIZE 2048 //keysize used to generate key (has to be 1024,2048,4096,or 8192)

#define DB_FNAME "sscdb.db" //SQLITE Database Filename(Will be generated if not found)
#define SSC_VERIFY_VARIABLES //Sanity check variables at minimal cost of speed

//Message Purposes
#define MSGSND 1 //Message Send(normal message)
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key from server
#define MSGREC 4 //Get new messages
#define AUTHUSR 9 //Purpose of message is to authenticate to the server.
//Server responses to the above.
#define MSGSND_RSP 5  
#define MSGREC_RSP 6
#define REGRSA_RSP 7
#define GETRSA_RSP 8
#define AUTHUSR_RSP 10

#endif
