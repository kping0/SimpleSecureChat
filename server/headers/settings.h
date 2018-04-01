#ifndef SSC_SETTINGSHFSRV
#define SSC_SETTINGSHFSRV
/*
* All configurable settings for SSC Server
*/
#define SRVDB "srvdb.db" //Server message database filename.

//Message Purposes
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
