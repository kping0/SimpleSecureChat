#/*
# * <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
# *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
# *
# *  This program is free software: you can redistribute it and/or modify
# *  it under the terms of the GNU General Public License as published by
# *  the Free Software Foundation, either version 3 of the License, or
# *  (at your option) any later version.
# *
# *  This program is distributed in the hope that it will be useful,
# *  but WITHOUT ANY WARRANTY; without even the implied warranty of
# *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# *  GNU General Public License for more details.
# *
# *  You should have received a copy of the GNU General Public License
# *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# */
all: sscssl.o sscasymmetric.o sscdbfunc.o base64.o serialization.o msgfunc.o
	echo "Compiling Objects: After this you need to do (make gui) or (make cli)"
sscssl.o: headers/sscssl.c headers/sscssl.h
	gcc -o sscssl.o -c headers/sscssl.c -O0 -Wall -Wextra -lssl -lcrypto -static -g3

sscasymmetric.o: headers/sscasymmetric.c headers/sscasymmetric.h
	gcc -o sscasymmetric.o -c headers/sscasymmetric.c -O0  -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3

sscdbfunc.o: headers/sscdbfunc.c headers/sscdbfunc.h
	gcc -o sscdbfunc.o -c headers/sscdbfunc.c -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3

base64.o: headers/base64.c headers/base64.h
	gcc -o base64.o -c headers/base64.c -Os -s -Wall -Wextra -static -g3
serialization.o: headers/serialization.h headers/serialization.c
	gcc -o serialization.o -c headers/serialization.c -O0 -Wall -Wextra -static -g3
gui.o: headers/gui.h headers/gui.c
	gcc `pkg-config --cflags gtk+-3.0` `pkg-config --cflags glib-2.0` -o gui.o -c headers/gui.c -O0 -g3 -Wall -Wextra -static `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0`
msgfunc.o: headers/msgfunc.c headers/msgfunc.h
	gcc -o msgfunc.o -c headers/msgfunc.c -O0 -g3 -static -Wall -Wextra -lsqlite3 -lcrypto -lssl
clean:	
	rm -f *.o testbinary* sscdb.db rsapublickey.pem rsaprivatekey.pem
gui: all gui.o
	gcc `pkg-config --cflags gtk+-3.0` `pkg-config --cflags glib-2.0` -o main.o -std=c99 -c sec_chat_client.c -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3 `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0`
	gcc -DSSC_GUI `pkg-config --cflags gtk+-3.0` `pkg-config --cflags glib-2.0` -o testbinary-gui gui.o main.o msgfunc.o sscdbfunc.o sscasymmetric.o sscssl.o base64.o serialization.o -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0`
	rm -f *.o
cli: all 
	gcc -o main.o -std=c99 -c sec_chat_client.c -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 -static -g3
	gcc -DSSC_CLI -o testbinary-cli main.o sscdbfunc.o msgfunc.o sscasymmetric.o sscssl.o base64.o serialization.o -O0 -Wall -Wextra -lssl -lcrypto -lsqlite3 
	rm -f *.o

gitprep: clean 
	rm -f public.pem README.md ../README.md
