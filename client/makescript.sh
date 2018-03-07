#!/bin/bash
cd dependencies/binn/ #YOU CAN GET THIS ON GITHUB!!
make
sudo make install #install binn
cd ../../
clear
echo "Compiling Main Application"
rm -f testbinary
gcc -o testbinary sec_chat_client.c -s -Os -Wall -Wextra -lssl -lcrypto -lbinn && chmod +x testbinary && strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id testbinary
