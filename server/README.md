<h1> SimpleSecureChat(Server) </h1>

Dependencies:
    
    OpenSSL(with development files)
    MYSQL/MariaDB(with development files)
  
  To compile install "make" and run:
  
      make #(Inside the server directory)
  To change the settings for your server, change the headers/settings.h file.Example:
  
      //#define DEBUG /* Uncomment for additional DEBUG information */
      ...
     
  To generate a certificate and a key(for use with the applicaton, run, or use your own certificate:
  
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 

  Note that the Client validates the server provided certificate against the file "client/public.pem", so if you are setting up your own server you need to copy the generated server public key(cert.pem) to your client(copy to client/public.pem).  
