#ifndef SERVER_H
#define SERVER_H

#include <stdlib.h> // Malloc
#include <string.h> // Strings
#include <sys/socket.h> // Sockets
#include <arpa/inet.h> // uint32_t
#include <netdb.h> // for addrinfo hints
#include <sys/types.h>
#include <unistd.h> // For close() and write() 
#include <cjson/cJSON.h> // For handling json
#include <stdio.h>
#include <fcntl.h> // For open()



#define BUF_SIZE 1024
#define MAX_BUFFER_SIZE 65536 // 64 KB is apparently more optimal 


// Used as a generic to return to the proper operation handler 
// typedef void* (*OperationFunc)(void* , void*); 



/*
 * The new message protocol sends a uint32_t value and a cjson string which contains metadata 
 * for the actual message/data. 
 * The uint32_t value provides the size for the cjson string so the server/client knows how much data
 *  to read. 
*/


int readMetadata(int sock, cJSON **config); 

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
// OperationFunc getOperation(uint64_t op);


/*
 * Init Sever 
    (returns a socket that is ready to receive connections)
    Args: 
        - char *port - desired port to start the server on 
        - int *sock -   The socket that gets opened. This takes a temp value (0)
                        that is updated once the server starts with the correct
                        socket number. 
*/

int initServer(char *port, int *sock); 

/* 
 * Starts the Server 
   (Runs an infinite loop that is ready to receive connections)
*/

int startServer(int socket, cJSON *config); 



/* 
    Handle the client connections
*/
int handle_client(int sock, cJSON *config); 

/* 
 * Read the client message and store everything inside of the message object
 *
*/
int readClientData(char *buffer, int socket, cJSON *metadata, int fd);






/* 
 * Write Data to disk
 * returns 0 on error
 * Args: 
 *      char *buff - A buffer containing information to write to file
 *      size_t buff_len - size/length of the buffer/data 
 *      int fd - A file descriptor 
 *
 *
*/
size_t writeData(char *buff, size_t buff_len, int fd); 


#endif