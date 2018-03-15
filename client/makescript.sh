#!/bin/bash
rm -f testbinary
sudo apt-get install libssl-dev libsqlite3-dev git gcc 
git clone https://github.com/liteserver/binn
cd binn/
make
sudo make install
cd ..
clear
echo "Compiling Main Application"
gcc -o sscssl.o -c headers/sscssl.c -Os -s -Wall -Wextra -lssl -lcrypto -static
gcc -o sscasymmetric.o -c headers/sscasymmetric.c -Os -s -Wall -Wextra -lssl -lcrypto -static
gcc -o sscdbfunc.o -c headers/sscdbfunc.c -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 -static
gcc -o main.o -c sec_chat_client.c -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 -static
gcc -o testbinary main.o sscssl.o sscasymmetric.o sscdbfunc.o -Os -s -Wall -Wextra -lssl -lcrypto -lsqlite3 
rm -f sscssl.o sscasymmetric.o sscdbfunc.o main.o 
