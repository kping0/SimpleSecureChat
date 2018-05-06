
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

#endif
