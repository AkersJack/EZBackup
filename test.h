#ifndef TEST_H
#define TEST_H

#include <cjson/cJSON.h>
#include <stdio.h>
#include "config.h"
#include "client.h"
#include <sys/stat.h>
#include <linux/limits.h>
#include <stdlib.h>
#include "server.h"
#include "database.h"



int test_FT(const int socket, cJSON *config);


/* 
 * Init a file container from a json item that contains a list of files.
 * files should be a cJSON pointer to a json list item if not returns 1;
 * On success returns 0; 
*/
int init_fileContainer(cJSON *files, struct fileContainer *fc);

#endif 