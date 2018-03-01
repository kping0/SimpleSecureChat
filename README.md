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


Message Idea:


 MESSAGE STRUCTURE 1:
 
  SSL_TO_SERVER{
 	ENCRYPTED_WITH_PUBLIC{
  		SIGNED_WITH_PRIVATE{
 			msg_id,
 			msg[],
 			flags/special
 		}
 	}
 }
 
 *MESSAGE STRUCTURE 2:
 
 SSL_TO_SERVER{
 ENCRYPED_WITH_PUBLIC{
     SIGNED_WITH_PRIVATE{AES_SESSION_KEY}
  	}
  	ENCRYPTED_WITH_SESSION_KEY{
 		msg_id,
 		msg,
 		flags/special
  	}
  }
