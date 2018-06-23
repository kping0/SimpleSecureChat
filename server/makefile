

#/*
# *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
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

security_flags = -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-check -pie -fPIE -Wall -Wextra -Wformat -Wformat-security -O3 -g -Wl,-z,relro,-z,now -lpthread

no_warning_flags = -Wno-unused-function -Wno-pointer-sign -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-result #get rid of annoying warnings

flags = $(security_flags) $(no_warning_flags) -D_GNU_SOURCE

SSCServer: main.o sscsrvfunc.o base64.o serialization.o hashing.o protected_malloc.o cstdinfo.o simpleconfig.o loadconfig.o
	gcc $(flags) -o SSCServer simpleconfig.o loadconfig.o base64.o sscsrvfunc.o main.o serialization.o hashing.o protected_malloc.o cstdinfo.o  `mysql_config --cflags --libs` -lcrypto -lssl
	rm -f *.o

main.o: secure_chat_server.c
	gcc $(flags) -o main.o -c secure_chat_server.c `mysql_config --cflags --libs` -lcrypto -lssl

sscsrvfunc.o: headers/sscsrvfunc.h headers/sscsrvfunc.c
	gcc $(flags) -o sscsrvfunc.o -c headers/sscsrvfunc.c `mysql_config --cflags --libs` -lssl -lcrypto

serialization.o: headers/serialization.c headers/serialization.h
	gcc $(flags) -o serialization.o -c headers/serialization.c

base64.o: headers/base64.h headers/base64.c
	gcc $(flags) -o base64.o -c headers/base64.c

hashing.o: headers/hashing.c headers/hashing.h
	gcc $(flags) -o hashing.o -c headers/hashing.c -lcrypto

protected_malloc.o: headers/protected_malloc.c headers/protected_malloc.h
	gcc $(flags) -o protected_malloc.o -c headers/protected_malloc.c

cstdinfo.o: headers/cstdinfo.c headers/cstdinfo.h
	gcc $(flags) -o cstdinfo.o -c headers/cstdinfo.c

simpleconfig.o: headers/simpleconfig.c headers/simpleconfig.h
	gcc $(flags) -o simpleconfig.o -c headers/simpleconfig.c

loadconfig.o: headers/loadconfig.c headers/loadconfig.h
	gcc $(flags) -o loadconfig.o -c headers/loadconfig.c

clean:
	rm -f *.o SSCServer* temp 
gitprep: clean
	rm -rf README.md headers/README.md ../README.md cert.pem key.pem

mysqlprep:
	echo "This needs to be run with Root!"
	sudo service mysqld start
	sudo mysql -u root -e "CREATE USER 'SSCServer'@'localhost' IDENTIFIED BY 'passphrase'"
	sudo mysql -u root -e "GRANT ALL PRIVILEGES ON *.* to 'SSCServer'@'localhost' IDENTIFIED BY 'passphrase'"

debiandeps:
	echo "Needs to be run with root!"
	sudo apt-get install mariadb-server libmariadb-dev default-libmysqlclient-dev libssl-dev 

fedoradeps:
	echo "Needs to be run with root!"
	sudo yum install mariadb-server mariadb-common mariadb-config mariadb-devel mariadb-libs mariadb-server-utils openssl-libs 

