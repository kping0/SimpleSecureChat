testbinary: main.o
	gcc `pkg-config --cflags gtk+-3.0` `pkg-config --cflags glib-2.0` -O0 -g3 -o testbinary main.o  `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0` -Wall -Wextra
	rm *.o
main.o: sscs_gui.c
	gcc `pkg-config --cflags gtk+-3.0` `pkg-config --libs glib-2.0` -O0 -g3 -o main.o -c sscs_gui.c  `pkg-config --libs gtk+-3.0` `pkg-config --libs glib-2.0` -Wall -Wextra		
