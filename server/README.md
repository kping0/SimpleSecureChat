<h1> SimpleSecureChat(Server) </h1>

Dependencies:
    
    OpenSSL(with development files)
    MYSQL/MariaDB(with development files)
  
  To compile install "make" and run:
  
      make #(Inside the server directory)
  To change the settings for your server, change the headers/settings.h file and recompile.Example:
  
      //#define DEBUG
      ...
     
  To generate a certificate and a key(for use with the applicaton, run, or use your own certificate:
  
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 

  To start/stop the server run:
  
      ./server_ctl start/stop
  
  To view the logs run:
  
      ./server_ctl log
      
  
  Note that the Client validates the server provided certificate against the file path defined in "client/settings.h" (definition HOST_CERT), so if you are setting up your own server you need to copy the generated server public key(cert.pem) to your client directory and set HOST_CERT accordingly. 

The Default logfile is "SSCServer.log".
