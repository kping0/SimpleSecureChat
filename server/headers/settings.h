#ifndef SSC_SETTINGSHFSRV
#define SSC_SETTINGSHFSRV

/*
* All configurable settings for SSC Server
*/

//keep defined for additional DEBUG information
//#define DEBUG

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
