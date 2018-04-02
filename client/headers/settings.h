#ifndef SSC_SETTINGSHF
#define SSC_SETTINGSHF

/*
* This file contains all the configurable settings for SimpleSecureChat
*/

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
