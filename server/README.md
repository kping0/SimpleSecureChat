SimpleSecureChat(Server)

Dependencies:
  1. OpenSSL(with development files)
  2. SQLite(with developement files)
  
  To compile install "make" and run:
  
      make #(Inside the server directory)
  To generate a certificate and a key(for use with the applicaton, run, or use your own certificate:
  
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 

  Note that this certificate (in this case "cert.pem") ALSO needs to be put in the client directory for server validation to prevent MITM attacks.
