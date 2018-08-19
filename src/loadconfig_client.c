
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

#include "loadconfig_client.h"

SCONFIG* loadconfig_client(void){
	debugprint();
	char* home_dir = secure_getenv("HOME");
	size_t home_dir_l = strlen(home_dir);
	size_t data_dir_l = home_dir_l + 17;
	char data_dir[data_dir_l];
	sprintf(data_dir,"%s/.ssc_conf/",home_dir);
	char config_file[data_dir_l + 10];
	sprintf(config_file,"%sssc_config",data_dir);
	SCONFIG* config = NULL;	
	if(sconfig_config_exists(config_file) == 0){
		if(mkdir(data_dir, S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST)cexit("Could not create ~/.ssc_local/ (errno == %d)\n",errno);
		config = sconfig_load(config_file);

		char log_file[data_dir_l + 14];
		sprintf(log_file,"%sssc_client.log",data_dir);
		char cert_file[data_dir_l + 9];
		sprintf(cert_file,"%scert.pem",data_dir);
		char pub_file[data_dir_l + 8];
		sprintf(pub_file,"%spub.pem",data_dir);
		char priv_file[data_dir_l + 9];
		sprintf(priv_file,"%spriv.pem",data_dir);
		char db_file[data_dir_l + 9];
		sprintf(db_file,"%ssscdb.db",data_dir);
	#ifndef RELEASE_IMAGE	
		sconfig_set_str(config,"HOST_NAME","127.0.0.1");
		/* you need to put the locally generated public cert at '~/.ssc_conf/cert.pem' if you are developing */
	#else
		sconfig_set_str(config,"HOST_NAME",DEFAULT_HOST_NAME);

		char default_certificate_b64[] = "-----BEGIN CERTIFICATE-----MIIFqzCCA5OgAwIBAgIJAIkYTZQy+843MA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAkRFMRkwFwYDVQQKDBBTaW1wbGVTZWN1cmVDaGF0MRswGQYDVQQDDBJTU0NTZXJ2ZXJfT2ZmaWNpYWwxJTAjBgkqhkiG9w0BCQEWFmtwaW5nMEBwcm90b25tYWlsLmNvbSAwHhcNMTgwNTA0MDUxMDU4WhcNMTgwNjAzMDUxMDU4WjBsMQswCQYDVQQGEwJERTEZMBcGA1UECgwQU2ltcGxlU2VjdXJlQ2hhdDEbMBkGA1UEAwwSU1NDU2VydmVyX09mZmljaWFsMSUwIwYJKoZIhvcNAQkBFhZrcGluZzBAcHJvdG9ubWFpbC5jb20gMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6UxVBu12yU3xuEGs3/eSjbL1lTsNJkYQ630XlyW5Ib5qc5STlCTem6wFma3FmXu+zOTrNgrsQDVkKP2edXp5EVX9LC931dvtg3ynmZ0uojSwedhM8j5gyPlRHPSrK6HDXXkAbQ8r/qYP5V60IfhHGns1JN1EcTsQ4sDfuat82Yrhi/4rsh8h2pLsLGsK67tMd+9bKYl8RrSFHWJjmx4m+NyzdXMprBRk6ieqdhbYEzA3OQYhlwR83NbhPbUovw2RSBYV4jorMf6aLfmK7zsSjPU3HALp2t76UHARvDOaRWfvcsGgHYDPOKomffBrQPmSIA5gUaCwlLHlLQtmUuhQubsNVPjSQ7xU4ecH54DuH87k+i9s617eRciv4S3iSYY2x2Jgwa1DDFJf1RCU6ufMM6mR/o4XPCVN4etVzAGeNO/7UBjsanLdi3cRKKXjdq1uS6JZRmbgRKB9ypkkZUUqbn7jDAI8YMe5q+rB8nvMjplxxtmZZc3AIdnNzJXpipxfDeZ2Gecq72p3sLBY3UE4qzdVsPpynWCrXGy4RtoQuXXafZm6iHbSofglokNo38L2LuvRGNRCt95OnmcVR8lCkmNTWVhrFz3RG4mTTlDyNexaoPsZxIdRJoKhTiecMPs4r3H3kfk/cllu9PtANrjwh7dom2/pjSYcjGJiRQkqR+MCAwEAAaNQME4wHQYDVR0OBBYEFPJzH6D3Og+a7osKrDRT5klP0fVrMB8GA1UdIwQYMBaAFPJzH6D3Og+a7osKrDRT5klP0fVrMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBALtyny/GsFP8i5tnlCtHKTPQ8LVJfHFFgC+c6QBkVH+zy3Yp5+tWwSPGs+Z6NPzMgD/9AxYsEIwc3ZAm8FOHJudc5bYRak3c8yAmINZizm6NSpxjKZfrzHYD2ETpzfdzl3QMKDWvgNSMDvDTmlj6RPDyL5oSOUbrRxOoZNcxIO93jkxiMqi71/mJpTGcN+yj0rUo9/uptc3O61Ywn3Admb7YELFxsu4NpL2SfSF78cqeNOA74fPJqK03R7fk57fST6CqdHcZe+4IfLvv1LhwuaEaEgSj8+kpvo2HWbxeqclj9maPT8SF+1J+ZY0xrDMmE0XdXDVc9p0a2aRDq/LkhKhYfsdjJbaWQfTeKPL/qcTiAGQeNffQB8g6NIJYtY78jnrRH6V1WnxFKoOqpEdMYuYcbwEcXEM43RJvxSzTST/WLHV2VYR0ThaLgvXmCtnRXyYSatf9mokQfmMwzp2Ynh/vjobJ3CsOGPfFiYhP4yuD9p31m/U7+MrFEONv8QFunXKEvszgpriFxeD9G5zjmvvIAvQ/gLrB/E88Bu1xi46iGdZNlGh3bke8i5vr1ktc7BBe3vyQVOdW0bOf6MNLWrr9qM2ZPN//f22HiBjUF5/UOP1ynQntE6QCoLnZUpvAfpIWFhUmxdGoRl0q2oxO8FgxbM8ATUPIMlhRQdX/PDk/-----END CERTIFICATE-----"; /* default server cert b64 */

		/* write certificate to a file */
		FILE* cert_file_fp = fopen(cert_file,"w");
		if(cert_file_fp == NULL)cexit("could not write certificate file");
		fprintf(cert_file_fp,"%s",default_certificate_b64);
		fclose(cert_file_fp);
	#endif
		sconfig_set_str(config,"HOST_PORT","5050");
		sconfig_set_str(config,"HOST_CERT",cert_file);
		sconfig_set_int(config,"KEYSIZE",4096);
		sconfig_set_str(config,"DB_FNAME",db_file);
		sconfig_set_str(config,"PUB_KEY",pub_file);
		sconfig_set_str(config,"PRIV_KEY",priv_file);
		sconfig_set_str(config,"LOG_FILE",log_file);
		sconfig_write(config);
	}
	else{
		config = sconfig_load(config_file);
	}
	if(!config)return NULL;
	return config;
}
