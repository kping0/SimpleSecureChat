<h2>Client</h2>
Dependencies:

    OpenSSL (sudo yum install openssl-devel || sudo apt-get install libopenssl-dev)
    SQLite 3 (DB Library) (sudo apt-get install libsqlite3-dev)
    Gtk+ 3.2 (Only if compiled with GUI)

To compile the client install "make" and run:

    make gui #(Run inside of the client directory)

To reset your instance of SimpleSecureChat-Client:

    make clean
    
To customize the client, change the headers/settings.h file. Example:

    #define HOST_NAME "xxx.xxx.xxx.xxx" //Server IP
    ...
