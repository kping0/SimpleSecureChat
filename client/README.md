<h2>Client</h2>
Dependencies:

    OpenSSL Development files
    SQLite 3 Development files
    Gtk+ 3.2 Development files (not necessary for the cli only version)
    NCurses Development files 

To compile the gui+cli client, install "make" and run:

    make 
   
To compile the cli version only, install "make" and run:

    make cli

To reset your instance of SimpleSecureChat-Client:

    make clean
    
To customize the client, change the headers/settings.h file. Example:

    #define HOST_NAME "xxx.xxx.xxx.xxx" //Server IP
    ...
