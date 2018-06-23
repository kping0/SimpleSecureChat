#include "loadconfig.h"

SCONFIG* loadconfig(void){
	char* home_dir = secure_getenv("HOME");
	size_t home_dir_l = strlen(home_dir);
	char data_dir[home_dir_l + 17];
	sprintf(data_dir,"%s/.ssc_conf/",home_dir);
	char config_file[home_dir_l + 17 + 10];
	sprintf(config_file,"%sssconfig",data_dir);
	char log_file[home_dir_l + 17 + 14];
	sprintf(log_file,"%sSSCServer.log",data_dir);
	SCONFIG* config = NULL;	
	if(sconfig_config_exists(config_file) == 0){
		if(mkdir(data_dir, S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST){
				cexit("Could not create ~/.ssc_local/ (errno == %d)\n",errno);
		}
		config = sconfig_load(config_file);
	#ifndef RELEASE_IMAGE
		sconfig_set_str(config,"SSCDB_SRV","localhost");
		sconfig_set_str(config,"SSCDB_USR","SSCServer");
		sconfig_set_str(config,"SSCDB_PASS","passphrase");
		sconfig_set_str(config,"SSCS_CERTFILE","cert.pem");
		sconfig_set_str(config,"SSCS_KEYFILE","key.pem");
		sconfig_set_str(config,"SSCS_KEYFILE_PW","test");
	#else
		/* TODO get usr input */
	#endif
		sconfig_set_int(config,"SSCS_LOGTOFILE",0);		
		sconfig_set_str(config,"SSCS_LOGFILE",log_file);
		sconfig_write(config);
	}
	else{
		config = sconfig_load(config_file);
	}
	if(!config)return NULL;
	return config;
}
