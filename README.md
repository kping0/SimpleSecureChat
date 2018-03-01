# SimpleSecureChat
A simple program written in C mainly using libOpenSSL for a Simple, yet Secure chat.

Requirements:
1. openssl-dev (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev) 
2. gcc (sudo yum install gcc || sudo apt-get install gcc)
3. glibc
4. Linux... 


To compile:

cli# rm -f SimpleSecureChat; gcc -o SimpleSecureChat secure_chat.c -lssl -lcrypto && chmod +x SimpleSecureChat
