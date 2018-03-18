testbinary: main.o sscdbfunc.o sscssl.o sscasymmetric.o binn.o 
	gcc -o testbinary main.o sscdbfunc.o sscasymmetric.o sscssl.o binn.o -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 
	rm -f *.o
binn.o: headers/binn.c headers/binn.h
	gcc -o binn.o -c headers/binn.c

sscssl.o: headers/sscssl.c headers/sscssl.h
	gcc -o sscssl.o -c headers/sscssl.c -Os -s -Wall -Wextra -lssl -lcrypto -static

sscasymmetric.o: headers/sscasymmetric.c headers/sscasymmetric.h
	gcc -o sscasymmetric.o -c headers/sscasymmetric.c -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 -static

sscdbfunc.o: headers/sscdbfunc.c headers/sscdbfunc.h
	gcc -o sscdbfunc.o -c headers/sscdbfunc.c -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 -static

main.o: sec_chat_client.c 
	gcc -o main.o -c sec_chat_client.c -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 -static
clean:	
	rm -f *.o testbinary sscdb.db rsapublickey.pem rsaprivatekey.pem
