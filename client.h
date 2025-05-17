#ifndef LIBARCH_H
#define LIBARCH_H


#include <stdint.h> 
#include <stdlib.h>
#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cjson/cJSON.h>
#include <math.h>
#include <errno.h> // Should be thread safe in modern C
#include <unistd.h>
#include <ctype.h>
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>


// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void*); 

struct custom_write_data{
        FILE *output_file; 
        const char *output_filename; 
        //cJSON *cj_obj; // Cjson object 
        uint64_t *total_written; // For compressed size
        uint64_t *total_read; // For uncompressed size 
        int sock; // For socket
};

struct Message{
    uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
    uint32_t size; // Size of the payload 
    uint32_t dsize; // Data size  
    uint32_t jsize; // Size of json file 
    uint64_t total_transfered; // Total amount of data transfered (can be NULL) 
    char *data; // Jason data but can be NULL for no data
                    
};

struct FileBuffer{
    uint64_t size; // Size of the buffer (set after allocation)
    char *buffer; // Going to just dynamically allocate this 
};


typedef struct{
    uint32_t upper;  // Upper half of a uint64_t
    uint32_t lower; // Lower half of a uint64_t
}uint64_s;

typedef struct{
        char units[3];
        double size; 

}sizeObject;

struct fileContainer{
        char **files; 
        unsigned int num_files; 

};

/* 
 * 0 = success
 * -1 = getaddrinfo() error
 *  1 = failed to connect error
 *  
 * Initializes the client (sets up the socket for connection)
*/
int initClient(const char *address, const char *port, int *sock);

int freeFileContainer(struct fileContainer *fc); 


#endif