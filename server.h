#ifndef SERVER_H
#define SERVER_H

#include <stdlib.h> // Malloc
#include <string.h> // Strings
#include <sys/socket.h> // Sockets
#include <arpa/inet.h> // uint32_t
#include <netdb.h> // for addrinfo hints
#include <sys/types.h>



#define BUF_SIZE 1024
#define MAX_BUFFER_SIZE 65536 // 64 KB is apparently more optimal 


// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void* , void*); 

// Contains all the possible operations (already defined in client.c)
typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 

struct MessageHeader{
    uint32_t operation; // Type of operation
    uint32_t size; // Size of the data coming in 
    uint32_t jsize; // Size of json data
    uint64_t fsize; // size of file/data
    
};

struct Message{
    uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
    uint32_t size; // Size of the entire payload 
    uint32_t jsize; // Size of json file 
    uint64_t fsize; // Size of the file/data
    // char payload[]; // File data and json data
    char *data;
};



// Generate MD5 File hash (need to free the returned value)
unsigned char* genHash(const char *fpath);

// Create a path to save the file to (need to free path)
char* savePath(const char* fname,  const char* path);


/* Add to tools.h combines 2 uint32 into a uint64 */
uint64_t combine_u32(uint32_t upper, uint32_t lower);



// Server-side check for incoming messages
int check_server_socket(int server_socket, int timeout_seconds);


// At this point the header should have been fully read and message_ptr contains that data
void* handle_file_transfer(void *sock_ptr, void *message_ptr);


/*
        Returns a function to handle the chosen operation
*/ 
OperationFunc getOperation(uint64_t op);
#endif