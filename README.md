<h1>SimpleSecureChat</h1>

 Simple & Secure e2e encrypted messaging application written in C.
 
 STILL IN DEVELOPMENT

Client Dependencies:
1. OpenSSL (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev) 
2. SQLite 3 (DB Library) (sudo apt-get install libsqlite3-dev)
3. Gtk+ 3.2 (Only if compiled with GUI)

To compile the client install "make" and run:

    make gui #(Run inside of the client directory)
    
To remove generated files(for example to reset the db):

    make clean
   
   
For Server instructions go to server/README.md
