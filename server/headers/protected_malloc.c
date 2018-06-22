
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

#include "protected_malloc.h"

/*
 * Check address for padding errors
 */
void sscs_chkaddr(void* ptr,const char* file,int line){
	void* orig = ptr-21; //get original allocated buffer
	byte* readpointer = (byte*)orig;	
	int chv = *(int*)readpointer; readpointer+=4;
	if(chv != SSCS_HEAP_MAGIC){
		cerror(" sscs_chkaddr() header checksum error - Called from %s - line %d\n",file,line);
		ccrit(" Heap Overflow at address %p likely,exiting \n",orig);
	#ifdef SSCS_CLIENT_FORK
	exit(1);
#else
	pthread_exit(NULL);
#endif
	}
	byte* rngbytes = readpointer; readpointer += 8;
	size_t bufsize = *(size_t*)readpointer; readpointer += 8;
	if(bufsize <= 0){
		cerror(" sscs_chkaddr() bufsize <= 0 - Called from %s - line %d\n",file,line);
		ccrit(" Heap Overflow at address %p likely,exiting \n",orig);
	}
	if(*readpointer != 0x0){
		cerror(" sscs_chkaddr() incorrect padding (!0x0) - Called from %s - line %d\n",file,line);
		ccrit(" Heap Overflow at address %p likely,exiting \n",orig);
	}	
	readpointer++;	
	readpointer+=bufsize;	
	if(*readpointer != 0x0){
		cerror(" sscs_chkaddr() (tail) incorrect padding - Called from %s - line %d\n",file,line);
		ccrit(" Heap Overflow at address %p likely,exiting \n",orig);
	}
	readpointer++;
	if(memcmp(rngbytes,readpointer,8)){
		cerror(" sscs_chkaddr() (tail) header-tail rng doesnt match - Called from %s - line %d\n",file,line);	
		ccrit(" Heap Overflow at address %p likely, exiting\n",orig);
	}
	readpointer+=8;
	chv = *(int*)readpointer;
	if(chv != SSCS_HEAP_MAGIC){
		cerror(" sscs_chkaddr() tail checksum error - Called from %s - line %d\n",file,line);
		ccrit(" Heap Overflow at address %p likely,exiting \n",orig);
	}
	return;	
}

size_t sscs_heap_object_size(void* ptr,const char* file,int line){
	sscs_chkaddr(ptr,file,line); //check address for padding issues 
	return *((size_t*)(ptr-9)); //return sizeof usable buffer
}

void sscs_ignore_result(long long int unused){ //used to suppress write() error
	(void)unused;
}
/*
 * Signal handler to receive SIGSEGV (if guard page is accessed)
 */
void sscs_cmalloc_sig_handler(int signum,siginfo_t *info,void* context){
	(void)context;
	(void)signum;
	char preamble[] = "[ERROR] Received SIGSEGV:";
	char msg[] = "Address not mapped\n";
	char msg2[] = "Access Error (to guard page?) -> Heap Overflow attempt possible\n";
	sscs_ignore_result(write(STDERR_FILENO,preamble,25));
	switch(info->si_code){
		case SEGV_MAPERR:
			sscs_ignore_result(write(STDERR_FILENO,msg,21));
			break;
		case SEGV_ACCERR:
			sscs_ignore_result(write(STDERR_FILENO,msg2,65));
			break;
		default:
			sscs_ignore_result(write(STDERR_FILENO,"unknown error\n",20));
			break;
	}
	fflush(stderr);
	exit(EXIT_FAILURE);
}

void sscs_cmalloc_init(void){
	srand((unsigned int)time(NULL));
	signal(SIGSEGV,SIG_DFL);
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sscs_cmalloc_sig_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV,&sa,NULL);
	return;
}

unsigned char *gen_rdm_bytestream (size_t num_bytes){  //generate semi-random bytestream
  unsigned char *stream = malloc(num_bytes);
  size_t i;
  for (i = 0; i < num_bytes; i++){
    stream[i] = rand ();
  }
  return stream;
}

/*
 * Allocate Buffer 
 */
void* sscs_cmalloc(size_t size,const char* file, int line){
	cdebug(" Called sscs_cmalloc() (Called from %s-%d)\n",file,line);
	if(size <= 0)return NULL;
	size_t origsize = size;
/*
 * Calculate size to allocate (must be a multiple of PAGESIZE)
 */ 
	size += 40; //add 40Bytes for Padding
	size_t alloc_len = size + PAGESIZE - (size % PAGESIZE) + PAGESIZE; //get next multiple of pagesize that fits size&metadata + guardpage length
	char* buf = aligned_alloc(PAGESIZE,alloc_len);
	if(!buf){
		cexit("cmalloc() could not allocate aligned memory (called from %s line %d)\n",file,line);
		return NULL;
	}
	memset(buf,0,alloc_len);
/*
 * Add a Guard Page to the end of the allocated buffer
 * Note that this has a HUGE memory overhead especially for small buffers -> cmalloc(10) -> ~8192B allocated 
 */
	if(mprotect(buf+(alloc_len-PAGESIZE),PAGESIZE,PROT_NONE) != 0){ //create a 4KB guard page 
		fprintf(stderr,"[ERROR] Could not add guard page (called from %s line %d): ",file,line);
		switch(errno){
			case EACCES:
				fprintf(stderr,"EACCES (Memory Access Error)\n");
				free(buf);
				return NULL;
				break;
			case EINVAL:
				fprintf(stderr,"EINVAL ( (internal)buf ptr !valid OR not correctly aligned)\n");			
				free(buf);
				return NULL;
				break;
			case ENOMEM:
				fprintf(stderr,"ENOMEM (Kernel struct allocation error OR invalid address range)\n");
				free(buf);
				return NULL;
				break;
			case EFAULT:
				fprintf(stderr,"EFAULT (Memory cannot be accessed)\n");
				free(buf);
				return NULL;
				break;
			default:
				fprintf(stderr,"Unknown Error\n");
				free(buf);
				return NULL;
				break;
		}
	}
/*
 * Write Metadata to the buffer
 */
	void* writepointer = buf;
	*(int*)writepointer = SSCS_HEAP_MAGIC; writepointer += 4; //add SSCS_HEAP_MAGIC  
	size_t* checkvar = (size_t*)gen_rdm_bytestream(8); //add secret magic
	*(size_t*)writepointer = *checkvar; writepointer += 8;
	*(size_t*)writepointer = origsize; writepointer += 8; //add size 
	*(char*)writepointer = 0x0; writepointer++; //padding
	void* retptr = writepointer; writepointer+=origsize; //actual buffer
	*(char*)writepointer = 0x0; writepointer++; //padding	
	*(size_t*)writepointer = *checkvar; writepointer += 8; 
	*(int*)writepointer = SSCS_HEAP_MAGIC; writepointer += 4; //add SSCS_HEAP_MAGIC
	free(checkvar);	
	return retptr;
}

void sscs_cfree(void* ptr,const char* file,int line){
	cdebug(" Called sscs_cfree() (Called from %s-%d)\n",file,line);
	if(ptr == NULL){
		cdebug(" ptr passed is NULL\n");
		return;
	}
	void* orig = ptr-21; //go back to original metasize buffer
	sscs_chkaddr(ptr,file,line);

/*
 * We need to calculate the size of the original buffer the way we allocated it so we can reverse the 
 * guard page to avoid some nasty bugs
 */
	size_t size = sscs_heap_object_size(ptr,file,line);
	size += 40;
	size_t alloc_len = size + PAGESIZE - (size % PAGESIZE) + PAGESIZE; //calculate original alloc_len
/*
 * Change the permissions on the page back to Read + Write
 */
	if(mprotect(orig+(alloc_len-PAGESIZE),PAGESIZE,PROT_READ | PROT_WRITE) != 0){ 
		fprintf(stderr,"[ERROR] Could not undo guardpage (called from %s line %d): ",file,line);
		switch(errno){
			case EACCES:
				fprintf(stderr,"EACCES (Memory Access Error)\n");
				return;
				break;
			case EINVAL:
				fprintf(stderr,"EINVAL ( (internal)buf ptr !valid OR not correctly aligned)\n");			
				return;
				break;
			case ENOMEM:
				fprintf(stderr,"ENOMEM (Kernel struct allocation error OR invalid address range)\n");
				return;
				break;
			case EFAULT:
				fprintf(stderr,"EFAULT (Memory cannot be accessed)\n");
				return; 
				break;
			default:
				fprintf(stderr,"Unknown Error\n");
				return;
				break;
		}
	}
	free(orig); //free buffer 
	return;	
}
