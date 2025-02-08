#include <stdlib.h> 
#include <stdio.h>
#include <errno.h> 
#include <linux/limits.h>
#include <string.h> 
#include <pthread.h> 
#include <stdbool.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include <cjson/cJSON.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#if defined(__APPLE__)
    #define explicit_bzero(ptr, size)   memset_s(ptr, size, 0, size)
#endif

/* 


Compile the server 
gcc -g -D TEST_SERVER server.c -o server 

Compile with cjson: 
gcc -g -D TEST_SERVER server.c -o server -l cjson

Socket Documentation: 
https://man7.org/linux/man-pages/man2/socket.2.html
https://man7.org/linux/man-pages/man7/socket.7.html
    
TCP Documentation: 
https://man7.org/linux/man-pages/man7/tcp.7.html


getaddrinfo
https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    

getnameinfo()
https://man7.org/linux/man-pages/man3/getnameinfo.3.html


recvfrom()
https://man7.org/linux/man-pages/man3/recvfrom.3p.html

getsockname() 
https://man7.org/linux/man-pages/man2/getsockname.2.html


sendfile() 
https://man7.org/linux/man-pages/man2/sendfile.2.html

Socket Domains: 
    - For IPV4 we use AF_INET 
    - For IPV6 we use AF_INET6 



Socket Types: 
    SOCK_STREAM

Can also use the bitwise OR operator on the type argument for socket to modify behavior: SOCK_NONBLOCK
    SOCK_CLOEXEC


Socket Protocol: 



SOCK_STREAM
    - Full-duplex byte stream 
    - Must be in a connected state before any data can be sent or received on it. 
    - A connection to another socket is created with a conneect() call. 
    - Once connected, data may be transferred using read() and write() calls or some variant of the send() and recv() calls. 
    - When session ahs been completed a close() may be performed. 
    - SOCK_STREAM ensures that data is not lost or duplicated. 
    - If a piece of data for which the peer protocol has buffer space cannot be successfully transmitted within a 
    reasonable length of time then the connection is to be considered dead. 

    If SO_KEEPALIVE is enabled on the socket the protocol checks in a protocol-specific manner if the other end is still alive.
    
    A SIGPIPE signal is raised if a process sends or receives on a broken stream. 

    Socket Return values: 
        On success a file descriptor for the new socket is returned. 
        On error -1 is returned, and errno is set to indicate the error.


getaddrinfo()
    - Helps with setting up the socket 
    - AF_UNSPEC allows getaddrinfo() to return a socket address for either IPV4 or IPV6 (so either or can be used)


getnameinfo() 
    Converts a socket address to a corresponding host and service, in a protocol-independent manner. 


select() 
    the first argument should be the highest_numbered file descriptor in any of the sets plus 1. 
    select() checks all file descriptors from 0 up to this number minus 1.
    So if your highest fd is 5 you pass 6(5 + 1) to check fds 0 through 5. 
    select() monitors a range of file descriptors 
    
    
*/


#define BUF_SIZE 1024
// #define MAX_BUFFER_SIZE 1048576 // 1 megabyte (apparently too big and inefficient)
// #define MAX_BUFFER_SIZE 4096 //  
// #define MAX_BUFFER_SIZE 65536 // 64 KB is apparently more optimal 
#define MAX_BUFFER_SIZE 131072 // 128 KB (same as the client buffer)


// Flags 
int w_flag = 0;  // write
int l_flag  = 0; // location (default is local dir but soon may be the coppied file location)
int p_flag = 0; // port
char *write_location; // Where to write files (if writing files)

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
    uint64_t dsize; // size of file/data
    
};

struct Message{
        uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
        uint32_t size; // Total size of the payload/message 
        uint32_t dsize; // Data size (size of data associated with this packet)
        uint32_t jsize; // Size of json file (if included)
        uint64_t total_transfered; // Total amount of data transfered (can be NULL)
        char *data; // JSON data but can be NULL for no data
};

// Need to free the hash
unsigned char* genHash(char *buff, size_t buff_size){
    unsigned char *hash = malloc(MD5_DIGEST_LENGTH); 
    
    MD5_CTX md5; 
    
    

    MD5_Init(&md5);
    
    MD5_Update(&md5, buff, buff_size); // Try this if slow we can split it into pieces
    // while(buff_size > 0){
    //     MD5_update(&md5, buff + offset, hbuff_size); 
    //     offset += hbuff_size;
    //     buff_size -= hbuff_size; 
    // }
    
    MD5_Final(hash, &md5);
    

    
    return hash;
}


// Generate MD5 File hash (need to free the returned value)
unsigned char* genHash_file(const char *fpath){
    FILE *fp = fopen(fpath, "rb");
    if(fp == NULL){
        perror("Error opening file");
        exit(1);
    }

    unsigned char *hash = malloc(MD5_DIGEST_LENGTH); 
    
    unsigned char buffer[4096];
    MD5_CTX md5; 
    size_t bytes; 
    

    MD5_Init(&md5);
    
    while((bytes = fread(buffer, 1, sizeof(buffer), fp)) != 0){
        MD5_Update(&md5, buffer, bytes);
    }
    MD5_Final(hash, &md5);
    
    fclose(fp);
    
    return hash;
    
}


// Create a path to save the file to (need to free path)
char* savePath(const char* fname,  const char* path){
    size_t path_len = strlen(fname) + strlen(path);
    char *save_location = malloc(path_len + 2); // For null terminator and possibly extra slash
    bzero(save_location, path_len + 2);
    if(path[strlen(path) - 1] == '/'){
        snprintf(save_location, path_len + 1, "%s%s", path, fname); 
    }else{
        snprintf(save_location, path_len + 2, "%s/%s", path, fname);      
    }

        
    return save_location;
}

// These handles should be made private (static) as they are different than the clients handles
// TODO: Implement this 
void* handle_message_transfer(void *sock_ptr, void *message_ptr){
    printf("Need to implement message transfer\n");

}

uint64_t combine_u32(uint32_t upper, uint32_t lower){
    uint64_t val = ((uint64_t)upper << 32) | lower; 
    return val; 

};


// Server-side check for incoming messages
int check_server_socket(int server_socket, int timeout_seconds){
    fd_set read_fs; 
    struct timeval timeout; 

    // Clear and set the socket set 
    FD_ZERO(&read_fs); 
    FD_SET(server_socket, &read_fs); 

    // Set timeout
    timeout.tv_sec = timeout_seconds; // sec 
    timeout.tv_usec = 0; // ms
    
    // Check if the socket is ready for reading 
    int ready = select(server_socket + 1, &read_fs, NULL, NULL, &timeout); 
    // int ready = select(server_socket + 1, &read_fs, NULL, NULL, NULL); 

    if (-1 == ready){
        perror("select error"); 
        return -1; 
    }else if (0 == ready){
        printf("Timeout occurred\n"); 
        return 0; 
    }

    return FD_ISSET(server_socket, &read_fs) ? 1 : 0; 
    
}


// int handle_file_transfer(void *sock, struct Message *mess, char *buff){
// int handle_file_transfer(void *sock, struct MessageHeader *mess, char *buff){
// At this point the header should have been fully read and message_ptr contains that data
void* handle_file_transfer(void *sock_ptr, void *message_ptr){
    int client_socket = *(int *)sock_ptr; 
    struct Message *message = (struct Message *) message_ptr; 
    // Check if a null-terminating character exists if not add one 
    char *jstring = malloc(message->jsize); 
    if(!jstring){
        perror("Failed to allocate memory");
        exit(1);
    }
    bzero(jstring, message->jsize);
    memcpy(jstring, message->data, message->jsize);
    if(jstring[message->jsize] != '\0'){
        jstring[message->jsize] = '\0';
    }
    // char *new_buffer = realloc(buffer, message->size); 
    ssize_t numbytes; 
    uint64_t buffsize = BUF_SIZE; // Holds the buffsize up to a certain point
    int header_csize = (BUF_SIZE - (sizeof(struct MessageHeader) + message->jsize)); // Size of file data in first header


    // printf("JSON String: %s\n", jstring);

    cJSON *json_object = cJSON_Parse(jstring);
    // Just for testing
    //printf("File Data: %s\n", file_data);
    // Write to file here

    // Parse the json string and turn it into a json object (REMEMBER: DELETE THIS OBJECT WHEN DONE!)

    int counter = 0; // Counter for size
                     // 
    bzero(jstring, message->jsize); 
    free(jstring); 
    jstring = NULL;
    

    
    
    // Track total bytes received 
    size_t total_received = 0; 
    size_t total_received_chunk = 0;
    cJSON* file_name = cJSON_GetObjectItemCaseSensitive(json_object, "name"); 
    if (file_name != NULL && cJSON_IsString(file_name)) {
        printf("Name: %s\n", file_name->valuestring);
    }

    
    
    int fd_write; 
    char *save_location;
    // Check if the location exists

    if(1 == w_flag){
        struct stat st_loc = {0};

        char *base_location = "./testcpy/";
        if(l_flag)
            base_location = write_location;
            

        if (stat(base_location, &st_loc) == -1) {
            // Directory doesn't exist
            //
            //mkdir(base_location, 0700);
            printf("Error: Write path %s doesn't exist!\n", base_location);
            exit(1);
        }
        save_location = savePath(file_name->valuestring, base_location); 
        printf("Save Location: %s\n", save_location);
        fd_write = open(save_location, O_WRONLY| O_CREAT |O_TRUNC, 0644);
        if (fd_write < 0){
            perror("fd open failure");
            exit(1);
        }

    }
    char basebuffer[8]; // Holds the basic buffer
    

    
    uint32_t eof = 0; 
    ssize_t total_written = 0; 
    size_t buffer_size;
    char *buffer;
    uint32_t bheader_dsize; 
    

    do{
        // printf("Waiting to receive basic header...\n"); 
        numbytes = recv(client_socket, basebuffer, 8, 0);
        // printf("Received Basic Header\n");
        if(numbytes == -1){
            perror("recv"); 
            close(client_socket); 
            break;
        }
        
    
        memcpy(&message->dsize, basebuffer, sizeof(uint32_t)); 
        memcpy(&eof, (basebuffer + 4), sizeof(uint32_t)); 
        eof = ntohl(eof); 
        message->dsize = ntohl(message->dsize); 
        
        // printf("New dsize: %u\n", message->dsize);
        // printf("EOF: %u\n", eof);

        
        
        
        
        
        
        numbytes = 0; 
        
        
        // Allocate receive buffer
        buffer_size = (message->dsize < MAX_BUFFER_SIZE) ? message->dsize : MAX_BUFFER_SIZE;
        buffer = malloc(buffer_size);
        bzero(buffer, buffer_size);
        if (!buffer) {
            perror("Failed to allocate buffer");
            return NULL;
        }
        
        // Receive loop 
        total_received_chunk = 0; 
        while (total_received_chunk < message->dsize){
            // Calculate remaining time to receive 
            size_t remaining = message->dsize - total_received_chunk; 
            size_t to_receive =  (remaining < buffer_size) ? remaining : buffer_size;
        
            
            // wait for socket to be ready 
            fd_set read_fds; 
            struct timeval timeout; 
            FD_ZERO(&read_fds); 
            FD_SET (client_socket, &read_fds); 
            timeout.tv_sec = 30; // 30 sec timeout
            timeout.tv_usec = 0; 
            
            int select_result = select(client_socket + 1, &read_fds, NULL, NULL, &timeout); 
            if(select_result <= 0){
                perror("select() failed or timed out"); 
                // free(buffer); 
                return NULL; 
            }
            // Receive data in chunks 
            ssize_t bytes_received = 0; 
            while (bytes_received < to_receive){
                // check_server_socket(client_socket, 12);
                // if (total_received >= message->fsize) { // Check inside the loop
                //     break; // Exit the inner loop if done
                // }
                ssize_t result = recv(client_socket, buffer + bytes_received, to_receive - bytes_received, 0);
                // printf("Result: %ld", result); 
                if (result <= 0){
                    if (0 == result){
                        printf("Connection closed by peer\n"); 
                    }else{
                        perror("recv() failed"); 
                    }
                    // free(buffer); 
                    // buffer = NULL; 
                    return NULL;  
                }
                bytes_received += result; 
                // total_received += result; 
                // printf("bytes_received: %lu\n", bytes_received);
        
            }
            
            // Process the received chunk here (write to file) 
            total_received_chunk += bytes_received; 
            total_received += bytes_received; 

            if(1 == w_flag){
                ssize_t written = write(fd_write, buffer, bytes_received);
                if(written != bytes_received){
                    close(fd_write); 
                    if(written == -1){
                        perror("writing error");
                        exit(1);
                    }
                    printf("Error when writing: Bytes received and bytes written are not equal. Received: %ld, Written: %ld\n", bytes_received, written);
                    exit(1);
                }
                total_written += written;            
                written = 0;
            }
        
            
            float percent = 100 * ((double)total_received_chunk/message->dsize);
            // printf("Progress: %zu/%u (%.1f%%) bytes\n", total_received_chunk, message->dsize, percent);
            printf("Total Received: %lu\n", total_received);
        }
        free(buffer);
        buffer = NULL; 

    }while(eof != 1);
    
    char* h = genHash(buffer, buffer_size);
    printf("MD5 Hash: "); 
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++){
            printf("%02"PRIx8, h[i]);  // %02x for lowercase hex, %02X for uppercase
    }
    printf("\n");
    // free(h);
    
    printf("Successfully received: %lu bytes\n", total_received);
    if (1 == w_flag){
        printf("Successfully wrote: %lu bytes to %s\n", total_written, save_location);
        // fhash = genHash_file(save_location); 
        free(save_location);
    }else{
        // fhash = NULL; 
    }
    



    size_t extra_bytes = 0; 
    ssize_t result; 

    // Clean up 
    explicit_bzero(buffer, buffer_size); 
    free(buffer); 
    buffer = NULL; 

    cJSON_Delete(json_object);
    json_object = NULL; 
    close(fd_write); 

    save_location = NULL;
    

    return h; 

}

OperationFunc getOperation(uint64_t op){
    OperationFunc *func;
    switch(op){
        case TEST_OPERATION:
            printf("Test Operation\n"); 
            // func = malloc(sizeof(handle_test));
            // return handle_test;
            break; // Technically don't need a break after a return but just in case. 
        case FILE_TRANSFER:
            // printf("File Transfer\n");
            // func = malloc(sizeof(handle_file_transfer)); 
            return handle_file_transfer;
            break;  
        case MESSAGE:
            printf("Message\n"); 
            // func = malloc(sizeof(handle_message_transfer)); 
            return handle_message_transfer;
            // return func;
            break;
        default: 
            printf("Invalid operation\n");
            return NULL;
            break;

    }
    
}



// TODO: Detect Endianness and handle accordingly for all floating point numbers
int serialize_MessageHeader(struct MessageHeader *s, char *buffer){
    uint64_t offset = 0; // Ensures memory is copied in the correct location
    
    // Serialize 'operation'
    uint64_t operation = htonl(s->operation);

    memcpy(buffer + offset, &operation, sizeof(uint64_t));

    


    uint64_t size = htonl(s->size);
    offset += sizeof(uint64_t); // Move to next memory location 
    memcpy(buffer + offset, &size, sizeof(uint64_t));
    
    
    return 0;  
}

typedef struct{
    uint32_t upper;  // Upper half of a uint64_t
    uint32_t lower; // Lower half of a uint64_t
}uint64_s;


// Splits a uint64_t into two 32 bit values stored in uint64_s
uint64_s split_u64(uint64_t val){
    uint64_s newval; 
    
    // Extract Lower 32 bits 
    newval.lower = (uint32_t)val; 

    // Extract the Upper 32 bits (using right shift)
    newval.upper = (uint32_t)(val >> 32); 
    return newval;



};



// int deserialize_header(struct MessageHeader *mess){
int deserialize_header(struct Message *mess){
    uint64_s val = split_u64(mess->total_transfered);

    mess->operation = ntohl(mess->operation); 
    mess->size = ntohl(mess->size);
    mess->jsize = ntohl(mess->jsize);
    mess->dsize = ntohl(mess->dsize);
    val.lower = ntohl(val.lower); 
    val.upper = ntohl(val.upper);
    mess->total_transfered = combine_u32(val.upper, val.lower); 
    
    return 0; 
}




//void handle_client(int client_socket){
void handle_client(void *sock){
    int client_socket = *((int*) sock); 
    printf("server: got connection on socket %d\n", client_socket);
    // char buffer[BUF_SIZE]; 
    ssize_t bytes_received; 
    int buffsize = BUF_SIZE; 
    unsigned char test_hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    

    // struct MessageHeader *mess = (struct MessageHeader *)malloc(sizeof(struct MessageHeader));
    // mess->operation = OPERATION_TEST; 
    // mess->size = 1000; 
    // struct Message *client_message = (struct Message *)malloc(sizeof(struct Message));
    struct Message *client_message = malloc(sizeof(struct Message));
    // struct MessageHeader *client_message = malloc(sizeof(struct MessageHeader));
    int offset = 0;
    int numbytes; 
    // char *buffer = malloc(BUF_SIZE);
    char *buffer = malloc(BUF_SIZE);
    int sock_check; 
    int t = 0;
    while(1){
        bzero(buffer, BUF_SIZE);
        if(!buffer){
            perror("malloc");
            exit(1);
        }
        buffsize = BUF_SIZE; 
        offset = 0; 
        // Receive data
        // sock_check = check_server_socket(client_socket, 1);
        // printf("Sock check (After): %d\n", sock_check);
        printf("Waiting for client...\n");
        numbytes = recv(client_socket, buffer, BUF_SIZE, 0);
        printf("Received: %d\n", numbytes);
        if(numbytes == -1){
            perror("recv"); 
            close(client_socket); 
            break;
        }
        else if(numbytes == 0){
            printf("Client disconnected gracefully (Socked FD: %d).\n", client_socket);
            break;
        }

      

      
        // buffer[numbytes] = '\0'; 
        // printf("server received: '%s'\n", buffer); 
        
        // Read what the client sent 
        memcpy(&client_message->operation, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->size, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->dsize, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->jsize, buffer + offset, sizeof(uint64_t)); 
        offset += sizeof(uint32_t);
        memcpy(&client_message->total_transfered, buffer + offset, sizeof(uint64_t)); 
        offset += sizeof(uint64_t);
    
        // printf("sizeof message header: %lu\n", sizeof(struct MessageHeader));
        deserialize_header(client_message);
        
        

        printf("Operation: %u\nSize: %u\nJsize: %u\nTotal Transfered: %lu\nData Size: %u\n", client_message->operation, client_message->size, client_message->jsize, client_message->total_transfered, client_message->dsize);
        // printf("Buffer: %s\n", buffer + sizeof(struct MessageHeader));

        if(client_message->operation > 3){
            printf("Error here \n"); 
        }

        client_message->data = buffer + offset; 
        OperationFunc selectedOP = getOperation(client_message->operation); 
        unsigned char *fhash = (unsigned char *)selectedOP(sock, client_message);

        
        // If the client is sending a file 
        // if(client_message->operation == FILE_TRANSFER){
            // handle_file_transfer(&client_socket, client_message);
            
            // char *jstring = malloc(client_message->jsize + 1); 

            // memcpy(jstring, buffer + offset, client_message->jsize);
            // printf("JSON String: %s\n", jstring);

            // // Parse the json string and turn it into a json object (REMEMBER: DELETE THIS OBJECT WHEN DONE!)
            // cJSON *json_object = cJSON_PARSE(jstring);

            // offset += client_message->jsize; // Skip the json 
            // free(jstring); 
            // cJSON_Delete(json_object);
            // handle_file_transfer(&client_socket, client_message, buffer + sizeof(struct MessageHeader));
        // }
        
        ssize_t sent_val; 
        if(w_flag){
            printf("MD5 Hash: ");
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                printf("%02"PRIx8, fhash[i]); // %02x for lowercase hex, %02X for uppercase
            }
            printf("\n");
            sent_val = send(client_socket, fhash, MD5_DIGEST_LENGTH, 0);
            

        }else{
            // Use test hash here
            sent_val = send(client_socket, test_hash, MD5_DIGEST_LENGTH, 0);
        }
        




        // Send response
        // const char *msg = "Hello from server!";  
        // check_server_socket(client_socket, 1);
        // char *msg = client_message; 
        // if(send(client_socket, msg, strlen(msg), 0) == -1){
        // if(send(client_socket, fhash, MD5_DIGEST_LENGTH, 0) == -1){
        if(sent_val == -1){
        // if(send(client_socket, m_buffer, 128, 0) == -1){
            perror("send"); 
        }else{ 
            printf("Sent response\n");
        }


     
        // if(send(client_socket, "ACK", 3, MSG_NOSIGNAL) < 0){
        // if(send(client_socket, "ACK", 3, MSG_NOSIGNAL) < 0){
        //     if(errno = EPIPE){
        //         printf("Client disconnected (broken pipe) (Socket FD: %d)\n", client_socket);
        //         break;
        //     }
        // }
        
    }
    explicit_bzero(buffer, BUF_SIZE); 
    free(buffer); 
    buffer = NULL;
    // free(mess);
    // free(m_buffer);
    explicit_bzero(client_message, sizeof(struct Message));
    free(client_message);
    client_message = NULL; 
    close(client_socket); 

}


#ifdef TEST_SERVER
int main(int argc, char *argv[]){

    int opt; 
    char *port = NULL;
    

    while((opt = getopt(argc, argv, "wl:p:")) != -1){
        // printf("OPT: %d\n", opt); 
        switch(opt){
            case 'w': 
                w_flag = 1; 
                break; 
            case 'l': 
                l_flag = 1; 
                write_location = optarg; 
                break; 
            case 'p':
                p_flag = 1;
                port = optarg; 
                break;
                
            default:
                break; 
        }
    }


    printf("NT Server started\n"); 

    // argv1 is port 

    if (argc < 2){
        fprintf(stderr, "Usage: %s port -options\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int gai, sfd, new_fd; 
    char buf[BUF_SIZE];
    ssize_t nread; 
    socklen_t peer_addrlen; 
    struct addrinfo hints; 
    struct addrinfo *result, *rp;
    struct sockaddr_storage peer_addr; 
    struct sockaddr_in server_addr;
    socklen_t server_addrlen = sizeof(server_addr);
    


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // ALlow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // Socket Stream
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol 
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    

    // char* port;
    // if (optind < argc) {  // Check if there are any non-option arguments
    //     printf("Non-option arguments:\n");
    //     for (int i = optind; i < argc; i++) {
    //         printf("%s ", argv[i]);
    //         port = argv[i]; 

    //     }
    //     printf("\n");
    // } else {
    //     printf("No non-option arguments.\n");
    //     if (argc < 2){
    //         fprintf(stderr, "Usage: %s port -options\n", argv[0]);
    //         exit(EXIT_FAILURE);
    //     }
        
    // }
    gai = getaddrinfo(NULL, port, &hints, &result);

    /* 
     * getaddrinfo() returns a list of address structures. 
        Try each address until we successfully bind(2). 
        If socket(2) (or bind(2)) fails, we close the socket
        and try the next address.  
    */
    
    for (rp = result; rp != NULL; rp = rp->ai_next){
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); 
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0){
            getsockname(sfd, (struct sockaddr *)&server_addr, &server_addrlen); 
            char ip_str[INET_ADDRSTRLEN];
            printf("Socket bound at address: %s:%d\n", ip_str, ntohs(server_addr.sin_port));
            break;  /* Success */
        } 
        // if(bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1){
        //     perror("server: bind"); 
        //     close(sfd);
        //     continue; 
        // }
        // break;
        close(sfd); 
    }
    
    freeaddrinfo(result); /* No longer needed */
    

    if (rp == NULL){ /* NO address succeeded*/
        fprintf(stderr, "Could not bind\n"); 
        exit(EXIT_FAILURE);
    }
    

    
    if(listen(sfd, 10) == -1){
        perror("listen"); 
        close(sfd); 
        exit(1);
    }
    
    if(1 == w_flag)
        printf("-w flag detected writing files to save location.\n");
    
    if(1 == l_flag)
        printf("Write location set to: %s\n", write_location);
    printf("server: waiting for connections...\n");
    
    peer_addrlen = sizeof(peer_addr);

    while(1){
        new_fd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addrlen); 
        printf("new fd:  %d\n", new_fd);
        // char host[NI_MAXHOST], service[NI_MAXSERV]; 
        // nread = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addrlen);
        
        
        
        
        if (new_fd == -1){
            perror("accept failed");
            continue; // Ignore failed request 
        } 
        

        handle_client(&new_fd);
        // handle_client(new_fd);

        

        
        // gai = getnameinfo((struct sockaddr *) &peer_addr, peer_addrlen, host, NI_MAXHOST, service,
        //                 NI_MAXSERV, NI_NUMERICSERV);
    

        // if (gai == 0)
        //     printf("Received %zd bytes from %s:%s\n", nread, host, service); 
        // else
        //     fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gai));


    
    }

    printf("At main end\n");
    close(new_fd);
    close(sfd);
    return 0;
}

#endif