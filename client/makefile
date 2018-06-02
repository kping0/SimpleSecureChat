
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
debug_flags = -O0 -g3 

security_flags = -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-check -pie -fPIE -Wall -Wextra -Wformat -Wformat-security -O3 -g -Wl,-z,relro,-z,now

flags = $(security_flags) -std=c99 -lpthread -D_POSIX_C_SOURCE=199309L -DSQLITE_THREADSAFE=1

gui_flags = -DSSC_GUI `pkg-config --cflags gtk+-3.0` `pkg-config --cflags glib-2.0` `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0`

gui: all gui.o sec_chat_client.c 
	gcc $(flags) $(gui_flags) -o main.o -c sec_chat_client.c -lssl -lcrypto -lsqlite3  
	gcc $(flags) $(gui_flags) -o SSCClient gui.o cli.o main.o msgfunc.o sscdbfunc.o sscasymmetric.o sscssl.o base64.o serialization.o -lssl -lcrypto -lsqlite3 -lpanel -lncurses
	rm -f *.o
all: sscssl.o sscasymmetric.o sscdbfunc.o base64.o serialization.o msgfunc.o cli.o
sscssl.o: headers/sscssl.c headers/sscssl.h
	gcc $(flags) -o sscssl.o -c headers/sscssl.c -lssl -lcrypto
sscasymmetric.o: headers/sscasymmetric.c headers/sscasymmetric.h
	gcc $(flags) -o sscasymmetric.o -c headers/sscasymmetric.c -lssl -lcrypto -lsqlite3 
sscdbfunc.o: headers/sscdbfunc.c headers/sscdbfunc.h
	gcc $(flags) -o sscdbfunc.o -c headers/sscdbfunc.c -lssl -lcrypto -lsqlite3
base64.o: headers/base64.c headers/base64.h
	gcc $(flags) -o base64.o -c headers/base64.c 
serialization.o: headers/serialization.h headers/serialization.c
	gcc $(flags) -o serialization.o -c headers/serialization.c
gui.o: headers/gui.h headers/gui.c
	gcc $(flags) $(gui_flags) -o gui.o -c headers/gui.c
cli.o: headers/cli.c headers/cli.h 
	gcc $(flags) -lpanel -lncurses -c headers/cli.c -o cli.o 
msgfunc.o: headers/msgfunc.c headers/msgfunc.h
	gcc $(flags) -o msgfunc.o -c headers/msgfunc.c -lsqlite3 -lcrypto -lssl
clean:	
	rm -f *.o SSCClient* sscdb.db rsapublickey.pem rsaprivatekey.pem
cli: all 
	gcc $(flags) -o main.o -c sec_chat_client.c -lssl -lcrypto -lsqlite3 
	gcc $(flags) -o SSCClient_cli main.o cli.o sscdbfunc.o msgfunc.o sscasymmetric.o sscssl.o base64.o serialization.o -lssl -lcrypto -lsqlite3 -lpanel -lncurses
	rm -f *.o
gitprep: clean 
	rm -f public.pem README.md ../README.md
