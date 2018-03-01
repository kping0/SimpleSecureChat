# SimpleSecureChat
A simple program written in C mainly using libOpenSSL for a Simple, yet Secure chat.

!!! STILL IN DEVELOPMENT NOT YET FUNCTIONAL!!!

Requirements:
1. openssl-dev (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev) 
2. gcc (sudo yum install gcc || sudo apt-get install gcc)
3. glibc
4. Linux... 


To compile:

cli# rm -f SimpleSecureChat; gcc -o SimpleSecureChat secure_chat.c -lssl -lcrypto && chmod +x SimpleSecureChat

Message_IDEA:
SSL_TO_SERVER{
    ENC_W_PUB{
        SIG_W_PRIV{
             MSG(MSG_ID,TIMESTAMP,MSG,FLAGS)
         }
    }
