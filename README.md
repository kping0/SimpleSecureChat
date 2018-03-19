<h1>SimpleSecureChat</h1>
A simple program written mainly in C using libssl for a Simple, yet Secure chat.

<p1 style="text-color:red"> STILL IN DEVELOPMENT </p1>

Dependencies:
1. OpenSSL (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev) 
2. SQLite 3 (DB Library) (sudo apt-get install libsqlite3-dev)
3. Binn (Data Serialization Library)(Pre included in headers folder) 

<h2> Client </h2>

To compile the client install "make" and run:

    make #(Run inside of the client directory)
    
To remove generated files(for example to reset the db):

    make clean
<h2> Server </h2>
To compile the server install "make" and run:

    make #(Run inside of the server directory)
    
Command to Create Server Certificate 

    server# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 

