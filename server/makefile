testbinaryserver: main.o sscsrvfunc.o base64.o serialization.o
	gcc -o testbinaryserver base64.o sscsrvfunc.o main.o serialization.o -lsqlite3 -lcrypto -lssl -Wall -Wextra -O0 -g3
	rm -f *.o
main.o: secure_chat_server.c
	gcc -o main.o -c secure_chat_server.c -lsqlite3 -lcrypto -lssl -Wall -Wextra -O0 -static -g3
sscsrvfunc.o: headers/sscsrvfunc.h headers/sscsrvfunc.c
	gcc -o sscsrvfunc.o -c headers/sscsrvfunc.c -lssl -lcrypto -Wall -Wextra -O0 -static -g3
serialization.o: headers/serialization.c headers/serialization.h
	gcc -o serialization.o -c headers/serialization.c -Wall -Wextra -O0 -static -g3
base64.o: headers/base64.h headers/base64.c
	gcc -o base64.o -c headers/base64.c -Wall -Wextra -O0 -static -g3
clean:
	rm -f *.o testbinaryserver temp 
cleanall:
	rm -f *.o testbinaryserver cert.pem key.pem temp
