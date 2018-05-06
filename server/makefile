

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

SSCServer: main.o sscsrvfunc.o base64.o serialization.o hashing.o
	gcc -o SSCServer base64.o sscsrvfunc.o main.o serialization.o hashing.o `mysql_config --cflags --libs` -lcrypto -lssl -Wall -Wextra -O
	rm -f *.o
main.o: secure_chat_server.c
	gcc -o main.o -c secure_chat_server.c `mysql_config --cflags --libs` -lcrypto -lssl -Wall -Wextra -O -static 
sscsrvfunc.o: headers/sscsrvfunc.h headers/sscsrvfunc.c
	gcc -o sscsrvfunc.o -c headers/sscsrvfunc.c `mysql_config --cflags --libs` -lssl -lcrypto -Wall -Wextra -O -static 
serialization.o: headers/serialization.c headers/serialization.h
	gcc -o serialization.o -c headers/serialization.c -Wall -Wextra -O -static 
base64.o: headers/base64.h headers/base64.c
	gcc -o base64.o -c headers/base64.c -Wall -Wextra -O -static 
hashing.o: headers/hashing.c headers/hashing.h
	gcc -o hashing.o -c headers/hashing.c -Wall -Wextra -O -static -lcrypto 
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

