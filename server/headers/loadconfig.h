#ifndef _LOADCONFIG_H
#define _LOADCONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "simpleconfig.h"
#include "settings.h"

SCONFIG* loadconfig(void);
	
#endif
