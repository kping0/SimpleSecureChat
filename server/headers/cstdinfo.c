
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
#include "cstdinfo.h"

static FILE* cinfo_out = NULL;
static FILE* cinfo_err = NULL;
static int cinfo_check_init = 0; 

void cinitfd(FILE* cinfo_out_file,FILE* cinfo_err_file){
	cinfo_out = cinfo_out_file;
	cinfo_err = cinfo_err_file;
	cinfo_check_init = 1;
#ifdef DEBUG
	fprintf(cinfo_out_file,"Custom Info & Error Messages Format: [SEVERITY](TIME)->CALLING_FUNCTION() [MESSAGE] \n");
#endif
	return;
}
void cerror_internal(const char* calling_function,char* format, ...){
	if(cinfo_check_init == 0)cinitfd(stdout,stderr); /* failsafe to default to stderr&stdout if cinitfd is never called */
	if(format == NULL)return;
	time_t t;
	time(&t);
	struct tm * timeinfo = localtime(&t);
	fprintf(cinfo_err,"[ERROR](%d:%d:%d_%d-%d-%d)->%s() ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,timeinfo->tm_mday,timeinfo->tm_mon+1,timeinfo->tm_year+1900,calling_function);
	va_list args;
	va_start(args,format);
	vfprintf(cinfo_err,format,args);
	fprintf(cinfo_err,"\n");
	va_end(args);
	return;
}
void cinfo_internal(const char* calling_function,char* format, ...){ 
	if(cinfo_check_init == 0)cinitfd(stdout,stderr);/* failsafe to default to stderr&stdout if cinitfd is never called */
	if(format == NULL)return;
	time_t t;
	time(&t);
	struct tm * timeinfo = localtime(&t);
	fprintf(cinfo_out,"[INFO](%d:%d:%d_%d-%d-%d)->%s() ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,timeinfo->tm_mday,timeinfo->tm_mon+1,timeinfo->tm_year+1900,calling_function);
	va_list args;
	va_start(args,format);
	vfprintf(cinfo_out,format,args);
	fprintf(cinfo_out,"\n");
	va_end(args);	
	return;
}
void cdebug_internal(const char* calling_function,char* format, ...){ 
	if(cinfo_check_init == 0)cinitfd(stdout,stderr);/* failsafe to default to stderr&stdout if cinitfd is never called */
	if(format == NULL)return;
#ifdef DEBUG /* Add wrapper so debug wrapper does not need to be added around every call to cdebug() */
	time_t t;
	time(&t);
	struct tm * timeinfo = localtime(&t);
	fprintf(cinfo_out,"[DEBUG](%d:%d:%d_%d-%d-%d)->%s() ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,timeinfo->tm_mday,timeinfo->tm_mon+1,timeinfo->tm_year+1900,calling_function);
	va_list args;
	va_start(args,format);
	vfprintf(cinfo_out,format,args);
	fprintf(cinfo_out,"\n");
	va_end(args);	
#else
	(void)format; /* Suppress build error */
	(void)calling_function;
#endif
	return;
}
void cexit_internal(const char* calling_function,char* format, ...){
	if(cinfo_check_init == 0)cinitfd(stdout,stderr);/* failsafe to default to stderr&stdout if cinitfd is never called */
	if(format == NULL)exit(EXIT_FAILURE);
	time_t t;
	time(&t);
	struct tm * timeinfo = localtime(&t);
	fprintf(cinfo_err,"[ERROR](%d:%d:%d_%d-%d-%d)->%s() ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,timeinfo->tm_mday,timeinfo->tm_mon+1,timeinfo->tm_year+1900,calling_function);
	va_list args;
	va_start(args,format);
	vfprintf(cinfo_err,format,args);
	fprintf(cinfo_err,"\n");
	va_end(args);
	exit(EXIT_FAILURE);
}
void ccrit_internal(const char* calling_function,char* format, ...){
	if(cinfo_check_init == 0)cinitfd(stdout,stderr);/* failsafe to default to stderr&stdout if cinitfd is never called */
	if(format == NULL)exit(EXIT_FAILURE);
	time_t t;
	time(&t);
	struct tm * timeinfo = localtime(&t);
	fprintf(cinfo_err,"[!!CRITICAL!!](%d:%d:%d_%d-%d-%d)->%s() ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,timeinfo->tm_mday,timeinfo->tm_mon+1,timeinfo->tm_year+1900,calling_function);
	va_list args;
	va_start(args,format);
	vfprintf(cinfo_err,format,args);
	fprintf(cinfo_err,"\n");
	va_end(args);
	exit(EXIT_FAILURE);
}

