testbinary: main.o sscdbfunc.o sscssl.o sscasymmetric.o base64.o serialization.o
	gcc -o testbinary main.o sscdbfunc.o sscasymmetric.o sscssl.o base64.o serialization.o -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 
	rm -f *.o

sscssl.o: headers/sscssl.c headers/sscssl.h
	gcc -o sscssl.o -c headers/sscssl.c -O0 -Wall -Wextra -lssl -lcrypto -static -g3

sscasymmetric.o: headers/sscasymmetric.c headers/sscasymmetric.h
	gcc -o sscasymmetric.o -c headers/sscasymmetric.c -O0  -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3

sscdbfunc.o: headers/sscdbfunc.c headers/sscdbfunc.h
	gcc -o sscdbfunc.o -c headers/sscdbfunc.c -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3

main.o: sec_chat_client.c 
	gcc -o main.o -std=c99 -c sec_chat_client.c -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3
base64.o: headers/base64.c headers/base64.h
	gcc -o base64.o -c headers/base64.c -Os -s -Wall -Wextra -static -g3
serialization.o: headers/serialization.h headers/serialization.c
	gcc -o serialization.o -c headers/serialization.c -O0 -Wall -Wextra -static -g3
clean:	
	rm -f *.o testbinary sscdb.db rsapublickey.pem rsaprivatekey.pem
