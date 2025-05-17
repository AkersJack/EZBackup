/* 
        config.c is used to manage the config file/s for the program 


*/


#ifndef CONFIG_H
#define CONFIG_H

#include <string.h> 
#include <stdio.h> 
#include <time.h>
#include <errno.h> 
#include <cjson/cJSON.h>


/* 
 *  Init The config file: 
 *       - Check if the file exists 
 *              - If it doesn't exist create the file and put in default values 
 *              - If exists return proper return code (also verify it can be opened 
 *                and has all the proper info in it).
 * 
 *      - Config file should be just ./config.json
*/
int initConfig();


/*
 * init a custom config for custom configuration files
*/

int init_custom_config(const char *path);


/* 
 * Read a custom config file 
*/
int readCustomConfig(const char *path, cJSON **obj);


/* 
 * If the config file doesn't exist create it
*/
int buildConfig();

/* 
 * Read the config file 
 * 
 * - This function should take in a cjson object and that object should be used 
 * to store the information from the json file. 
*/
int readConfig(cJSON **obj);

/* 
 * Write changes to the config file 
 * Should just take in the cjson object and write that to the file 
 *      - If possible it would be good if you could only change 1 part of the file
 *        (the part that was changed/edited) however I think this is far more difficult 
 *        than just writing the entire object to the file overwritting whatever was currently there.
*/
int writeConfig();


/* Check to make sure the file isn't corrupted and it has the necessary structure
 * This gets called in initConfig()
*/
int checkFile(); 



/* Default JSON config (incase of errors revert to a default config value)
 *
*/


#endif