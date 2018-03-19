testbinaryserver: binn.o main.o sscsrvfunc.o
	gcc -o testbinaryserver sscsrvfunc.o main.o binn.o -lsqlite3 -lcrypto -lssl -Wall -Wextra -Os -s 
	rm -f *.o
binn.o: headers/binn.c headers/binn.h
	gcc -o binn.o -c headers/binn.c -static
main.o: secure_chat_server.c
	gcc -o main.o -c secure_chat_server.c -lsqlite3 -lcrypto -lssl -Wall -Wextra -Os -s -static
sscsrvfunc.o: headers/sscsrvfunc.h headers/sscsrvfunc.c
	gcc -o sscsrvfunc.o -c headers/sscsrvfunc.c -lssl -lcrypto -Wall -Wextra -Os -s -static
clean:
	rm -f *.o testbinaryserver temp 
cleanall:
	rm -f *.o testbinaryserver cert.pem key.pem temp
