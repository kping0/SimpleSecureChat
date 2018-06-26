
/*
 *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
 *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* modconf - binary to change SSC settings easily */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "simpleconfig.h"
#include "cstdinfo.h"

void usage(char* argv[]){
	fprintf(stdout,"USAGE:   %s [TYPE] [LABEL] [DATA]\n",argv[0]);
	fprintf(stdout,"EXAMPLE: %s int label_for_integer 10\n",argv[0]);
	fprintf(stdout,"EXAMPLE: %s str label_for_string this is sample string\n",argv[0]);
	fprintf(stdout,"EXAMPLE: %s data label_for_data path_to_file_with_data\n",argv[0]);
	fprintf(stdout,"EXAMPLE: %s unset label_to_be_removed\n",argv[0]);
	exit(EXIT_FAILURE);
}
int main(int argc,char* argv[]){
	if(argc <= 2)usage(argv);
	char* home_dir = secure_getenv("HOME");
	size_t home_dir_l = strlen(home_dir);
	char data_dir[home_dir_l + 17];
	sprintf(data_dir,"%s/.ssc_conf/",home_dir);
	char config_file[home_dir_l + 17 + 10];
	sprintf(config_file,"%sssc_config",data_dir);
	SCONFIG* config = NULL;	
	if(sconfig_config_exists(config_file) == 0){
		if(mkdir(data_dir, S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST){
				cexit("Could not create ~/.ssc_conf/ (errno == %d)\n",errno);
		}
	}
	config = sconfig_load(config_file);
	int typeofdata = 0;
	if(strcmp(argv[1],"int") == 0){
		if(argc <= 3)usage(argv);
		typeofdata = 1;
	}
	else if(strcmp(argv[1],"str") == 0){
		if(argc <= 3)usage(argv);
		typeofdata = 2;
	}
	else if(strcmp(argv[1],"data") == 0){
		if(argc <= 3)usage(argv);
		typeofdata = 3;
	}
	else if(strcmp(argv[1],"unset") == 0){ 
		if(argc <= 2)usage(argv);
		typeofdata = 4; 
	}
	else{
		fprintf(stderr,"%s is not a valid datatype. Valid options are int, str, data & unset\n",argv[1]);
		return -1;
	}
	char* label = argv[2];	
	sconfig_unset(config,label);
	int x = 0;
	int y = 0;
	
	if(typeofdata == 1){
		sconfig_set_int(config,label,atoi(argv[3]));
	}
	else if(typeofdata == 2){
		int string_elements = argc - 3;
		for(x=0;x<string_elements;x++){
			y += strlen(argv[x+3]) + 1;
		}
		char str[y];
		memset(str,0,y);
		for(x=0;x<string_elements-1;x++){
			strcat(str,argv[x+3]);
			strcat(str," "); /* only add whitespace if there is another element in argv[] */
		}	
		strcat(str,argv[x+3]);
		sconfig_set_str(config,label,str);
	}
	else if(typeofdata == 3){
		FILE* datafile = fopen(argv[3],"r");
		if(!datafile)cexit("could not open file");
		fseek(datafile,0,SEEK_END);
		long data_length = ftell(datafile);
		fseek(datafile,0,SEEK_SET);
		byte data_buf[data_length];
		fread(data_buf,1,data_length,datafile);
		sconfig_set(config,label,data_buf,data_length);
		fclose(datafile);
	}
	/* 
	 * another else statement for (typeofdata == 4) is not neccessary, because the item has already 
	 * been removed.
	 */
	sconfig_write(config);
	return 0;	
}
