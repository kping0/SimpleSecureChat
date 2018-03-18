# SimpleSecureChat
A simple program written in C mainly using libOpenSSL for a Simple, yet Secure chat.

PRE-ALPHA

Requirements:
1. OpenSSL (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev) 
4. SQLite 3 (DB Library) (sudo apt-get install libsqlite3-dev)

To compile the client install "make" and run:

    make #(Run inside of the client directory)
To cleanup:

    make clean
    
Debugging with ncat: 

    server# ncat --ssl -klvp 5050 --ssl-key key.pem --ssl-cert cert.pem 


Command to Create Server Certificate 

    server# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 

