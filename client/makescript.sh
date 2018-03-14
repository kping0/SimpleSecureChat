#!/bin/bash

#cd dependencies/binn/ #YOU CAN GET THIS ON GITHUB!!
#make
#sudo make install #install binn
#cd ../../
sudo apt-get install libssl-dev # sudo yum install openssl-devel on fedora
sudo apt-get install libsqlite3-dev
git clone https://github.com/liteserver/binn
cd binn
make 
sudo make install
cd ..
clear
echo "Compiling Main Application"
rm -f testbinary
gcc -o testbinary secure_chat.c -s -Os -Wall -Wextra -lssl -lcrypto -lbinn -lsqlite3 && strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id testbinary
