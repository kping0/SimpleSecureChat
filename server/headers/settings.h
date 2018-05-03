
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
* All configurable settings for SSC Server
*/

//keep defined for additional DEBUG information
#define DEBUG

/* Settings for MySQL (MariaDB) */
#define SSCDB_SRV "localhost"
#define SSCDB_USR "SSCServer"
#define SSCDB_PASS "passphrase"

#define SSC_VERIFY_VARIABLES //sanity checks variables at a minimal cost of performance for security (comment out for tiny increase in speed)

//msgp - client/server response definitions
#define MSGSND 1 //Message Send(normal message)
#define MSGREC 4 //Get new messages 
#define REGRSA 2 //Register user in association with an rsa public key
#define GETRSA 3 //Get user public key
#define MSGSND_RSP 5 //Server response to MSGSND
#define MSGREC_RSP 6 //Server response to MSGREC
#define REGRSA_RSP 7 //Server response to REGRSA
#define GETRSA_RSP 8 //Server response to GETRSA
#define AUTHUSR 9 //Sent from client to authenticate

#endif
