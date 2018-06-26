#ifndef _LOADCONFIG_CLIENT_H
#define _LOADCONFIG_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "simpleconfig.h"
#include "cstdinfo.h"
#include "settings.h" 

SCONFIG* loadconfig_client(void);

#endif /* _LOADCONFIG_CLIENT_H */
