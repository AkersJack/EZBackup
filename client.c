// Check if sendfile exists
#if defined(__linux__)
    #include <sys/sendfile.h>
    #define HAVE_SENDFILE 1
#elif defined(__FreeBSD__) || defined(__APPLE__)
    // BSD systems have different sendfile implementation 
    #include <sys/types.h> 
    #include <sys/socket.h> 
    #include <sys/uio.h> 
    #define HAVE_SENDFILE 1
#else
    #define HAVE_SENDFILE 0
#endif

#include "client.h"
#include <fcntl.h>
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
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include <cjson/cJSON.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <time.h> 
#include <openssl/md5.h> 


/* 

Compile with cjson: 
gcc -g -D TEST_MAIN client.c -o client -l cjson 

OR if we define main:
gcc -g client.c -o client -l cjson 


Compile with hash gen: 
gcc -g client.c -o client -l cjson -l ssl -l crypto

Instead of reading a file into buffer and then sending the buffer can we just read the file directly 
into a send? 

*/
// Default buffer size 
#define BUF_SIZE 1024 

#define MAX_FNAME_LENGTH 4096 // Maximum length a filename can be 



                        


// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void* , void*); 

struct Message{
    uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
    uint32_t size; // Size of the payload 
    uint32_t jsize; // Size of json file 
    uint64_t fsize; // Size of the file/data
    // char payload[]; // json data (contains info about the file or other info)
    char *data;
};

struct FileBuffer{
    uint64_t size; // Size of the buffer (set after allocation)
    char *buffer; // Going to just dynamically allocate this 
};

// Contains all the possible operations
typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 


#if !HAVE_SENDFILE
/* custom sendfile implementation if not available 
 *
 * From MAN: 
  ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset, size_t count); 



*/

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count){
    
    return 0; 
}

#endif 

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

uint64_t combine_u32(uint32_t upper, uint32_t lower){
    uint64_t val = ((uint64_t)upper << 32) | lower; 
    return val; 

};

// Generate MD5 File hash (need to free the returned value)
unsigned char* genHash(const char *fpath){
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



// TODO: Detect Endianness and handle accordingly for all floating point numbers (probably don't need to do that)
// Need to use uint64_t values (or similar) htonl and ntohl only output uint32_t values 
// Need to split the 64 bit number into a high 32 bit number and a low 32 bit number 
// Once split we can encode them and send from the client to the server
// The server will then decode and reassemble the 64 bit number 
int serialize_Message(struct Message *s, char *buffer){


    uint32_t offset = 0; // Ensures memory is copied in the correct location
    

    // Serialize 'operation'
    uint32_t operation = htonl(s->operation);
    memcpy(buffer + offset, &operation, sizeof(uint32_t)); // + 0

    


    uint32_t size = htonl(s->size);
    offset += sizeof(uint32_t); // Move to next memory location 
    memcpy(buffer + offset, &size, sizeof(uint32_t)); // + 4


    
    offset += sizeof(uint32_t);
    uint32_t jsize = htonl(s->jsize);
    memcpy(buffer + offset, &jsize, sizeof(uint32_t)); // + 8

    uint64_s sv = split_u64(s->fsize);
    // printf("Split value (upper): %u\n", sv.upper);
    // printf("Split value (lower): %u\n", sv.lower);
    
    
    // uint64_t test_combine = combine_u32(sv.upper, sv.lower);
    // printf("Test combine: %lu\n", test_combine);

    offset += sizeof(uint32_t);
    uint32_t fsize_lower = htonl(sv.lower);
    memcpy(buffer + offset, &fsize_lower, sizeof(uint32_t)); // + 12
                                                             
    offset += sizeof(uint32_t);
    uint32_t fsize_upper = htonl(sv.upper);
    memcpy(buffer + offset, &fsize_upper, sizeof(uint32_t)); // + 16
                                                       //

    offset += sizeof(uint32_t); 
    
    // Subtract sizeof(uint64_t) * 3 as those are the 3 uint64_ts we just serialized
    // memcpy(buffer + offset, s->payload, s->jsize);
    
    memcpy(buffer + offset, s->data, s->jsize); // + 20
    

    // offset += s->jsize; 
    
    // Copy the file data into the buffer. 
    // memcpy(buffer + offset, s->payload + s->jsize, s->fsize);
    // memcpy(buffer + offset, s->data + s->jsize, s->fsize); // + s->jsize

    
    return 0;  
}

/*
 * @ char *f - 
 * @ char *buff - 
 * @ uint64_t buff_size - 
*/
int readFileIntoBuffer(char *f, struct FileBuffer *buff){
    // Open the file
    
    FILE *file; 
    file = fopen(f, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }
    
    size_t total_bytes_read = 0; 
    while(!feof(file)){
        size_t bytes_read = fread(buff->buffer + total_bytes_read, 1, (buff->size - total_bytes_read), file);
        // if (bytes_read == 0 && ferror(file)){
        //     perror("Error reading file");
        //     exit(1); 
        // }
        total_bytes_read += bytes_read;  
        if (total_bytes_read >= buff->size){
            buff->size += 1024; // Increase buffer size by 1024
            buff->buffer = realloc(buff->buffer, buff->size); // resize the buffer
            if (!buff->buffer){
                perror("Failed to reallocate memory");
                fclose(file); 
                return 1; 
            }
        }

    }
    printf("Total bytes read: %lu\n", total_bytes_read);
    // Just so I don't use more memory than I need to attempt to resize the buffer down 
    char *newbuffer = realloc(buff->buffer, total_bytes_read + 1);
    if(newbuffer){
        buff->buffer = newbuffer;
        buff->size = total_bytes_read + 1;
    }else{
        printf("Buffer reallocation failed; original buffer is still intact. \n");
    }
    
    return 0; 

}


// Custom implementation
// Sock, fd, &offset, count (size of the file)
// ssize_t sendfile2(int out_fd, int in_fd, off_t *offset, size_t count){
ssize_t sendfile2(int out_fd, int in_fd, off_t *offset, size_t count){
    size_t buffsize = 8192; // 8KB but can be increased or decreased as needed
    // ssize_t read(fd, buf, count); 
    //
    char buffer[buffsize]; 
    size_t total_sent = 0; 
    
    
    FILE *fp = fdopen(in_fd, "r");  
    if(!fp){
        perror("fdopen");
        fclose(fp); 
        return -1; 
    }
    
    // Set file position if offset is provided
    if(offset != NULL){
        if(fseek(fp, *offset, SEEK_SET) != 0){
            return -1;
        }
    }

    size_t bytes_remaining = count; 
    
    while (bytes_remaining > 0){
        size_t chunk_size = bytes_remaining < buffsize ? bytes_remaining : buffsize;
        size_t bytes_read = fread(buffer, 1, chunk_size, fp); 

        if(bytes_read == 0){
            if(ferror(fp)){
                perror("Error reading file"); 
                return -1; 
            }
            break; // EOF reached 
        }
        size_t bytes_written = 0; 
        // Send data through socket 
        while(bytes_written < bytes_read){
            ssize_t result = send(out_fd, buffer + bytes_written, bytes_read - bytes_written, 0); 
            if(result < 0){
                // Handle EINTR by continuing 
                if (errno = EINTR){
                    continue; 
                }
                // Handle EAGAIN/EWOULDBLOCK for non-blocking sockets 
                if(errno == EAGAIN || errno == EWOULDBLOCK){
                    // Should use select/pool/epool here
                    usleep(1000); // Sleep for 1ms before retrying
                    continue;
                }
                perror("Error sendfile2()"); 
                return -1; 
            }

            bytes_written += result;
        }
        
        total_sent += bytes_read; 
        bytes_remaining -= bytes_read; 
        
        // Update offset if provided 
        if (offset != NULL){
            *offset += bytes_read; 
        }

    }
 
    fclose(fp); 
    return total_sent; 
}


// ALready have this in recurse.c so can reuse it
char* getFname(char *p){ 
    char *file_name = strrchr(p, '/');
    if(file_name == NULL){
        file_name = p; 
    }else{
        file_name++; 
    }
    return file_name; 
}


cJSON* createJSON(char *filePath){
    // Create JSON object 
    cJSON *root = cJSON_CreateObject(); 
    struct stat file_stat; 
    

    char *fileName = getFname(filePath); 
    printf("File Name: %s\n", fileName);
    // getFext(fileName);
    // Add key value pairs to the root object 
    cJSON_AddStringToObject(root, "name", fileName);
    cJSON_AddStringToObject(root, "path", filePath);
    if(stat(filePath, &file_stat) == 0){
        cJSON_AddNumberToObject(root, "st_size", file_stat.st_size);
        // cJSON_AddNumberToObject(root, "st_ino", file_stat.st_ino);
        // cJSON_AddNumberToObject(root, "st_mode", file_stat.st_mode);
    //     cJSON_AddNumberToObject(root, "st_nlink", file_stat.st_size);
    //     cJSON_AddNumberToObject(root, "", file_stat.st_size);
    //     cJSON_AddNumberToObject(root, "", file_stat.st_size);
    // }
    // 
    }else{
        perror("stat");
        cJSON_Delete(root);
        exit(1); 
    }


    // Used for testing only can comment out once done 
    char *json_string = cJSON_Print(root); 

    // FILE *fp = fopen("output.json", "w"); 
    
    // if(fp)
    //     fputs(json_string, fp);
    

    // fclose(fp); 
    // printf("JSON size: %lu\n", strlen(json_string));
    printf("JSON Data: %s\n", json_string);
    free(json_string);

    return root;
}

// Returns:
//  1 if socket is ready to receive
//  0 if socket would block
// -1 on error
// int check_socket_ready_to_receive(int sockfd) {
//     fd_set read_fds;
//     struct timeval timeout;
    
//     FD_ZERO(&read_fds);
//     FD_SET(sockfd, &read_fds);
    
//     timeout.tv_sec = 0;  // Immediate timeout
//     timeout.tv_usec = 0;
    
//     int result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
//     if (result < 0) {
//         perror("select");
//         return -1;
//     }
    
//     return FD_ISSET(sockfd, &read_fds);
// }


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


void* handle_file_transfer(void *sock_ptr, void* message_ptr){
    int sock = *(int *)sock_ptr; 
    struct Message *message = (struct Message *)message_ptr; 

    // Free user_input_buffer
    char *user_input_buffer = malloc(BUF_SIZE); 
    int user_input_size = BUF_SIZE; // Current size of user_input_buffer
    int data_length = 0; // total amount of data that has been entered
    int fd; 
    
                         


    data_length = 0; 
    do{
        bzero(user_input_buffer, user_input_size);
        printf("Enter File Location: ");
        // Get user input 
        while(fgets(user_input_buffer + data_length, user_input_size - data_length, stdin) != NULL){
            data_length += strlen(user_input_buffer + data_length); 
            

            // User pressed enter and is done entering data
            if(data_length > 0 && '\n' == user_input_buffer[data_length - 1]){
                // user_input_buffer[data_length - 1] = '\0'; 
                user_input_buffer[data_length - 1] = '\0'; 
                break; 
            }

            if(data_length >= user_input_size - 1){
                user_input_size += BUF_SIZE; 
                user_input_buffer = realloc(user_input_buffer, user_input_size); 
                if(!user_input_buffer){
                    perror("realloc user_input_buffer failed"); 
                    exit(EXIT_FAILURE);
                }
            }
        }
        // printf("user_input_buffer: %s\n", user_input_buffer);
        fd = open(user_input_buffer, O_RDONLY); 
        if(-1 == fd){
            perror("Failed to open file"); 
            data_length = 0; 
        }
    }while(0 == fd || fd == -1);

    // printf("User Input: %s\n", user_input_buffer); 

    cJSON *jsonObject = createJSON(user_input_buffer); 

    // Generate file hash 
    unsigned char *fhash; 
    fhash = genHash(user_input_buffer);
    

    

    explicit_bzero(user_input_buffer, user_input_size);
    free(user_input_buffer); 
    user_input_buffer = NULL;
    
    char *json_string = cJSON_Print(jsonObject); 
    message->jsize = strlen(json_string); 
    // If you want the null terminating character just add 1 and u will get it
    // If you only want json data just do message->jsize
    message->data = malloc(message->jsize); 
    memcpy(message->data, json_string, message->jsize); 
    // message->data[message->jsize] = '\0'; 

    explicit_bzero(json_string, message->jsize); 
    free(json_string);
    json_string = NULL; 

    cJSON_Delete(jsonObject);

    // Get file info (call stat)
    struct stat st; 
    if(fstat(fd, &st) == -1){
        perror("failed to get file status");
        close(fd); 
        exit(1);
    }
    message->fsize = (uint64_t)st.st_size; 
    
    
    // This is for the 1 uint64_t and 3 uint64_t in the header
    uint64_t f_info = (sizeof(uint32_t) * 3) + (sizeof(uint64_t));
    message->size = message->jsize + f_info; 
    // printf("Size of message: %u\n", message->size); 
    
    // Header Data to be transfered
    char *data = malloc(message->size); 
    bzero(data, message->size);
    if(!data){
        perror("Data malloc failed"); 
        exit(1);
    }

    printf("Operation: %u, Size: %u, jsize: %u, fsize:%lu \n", message->operation, message->size, message->jsize, message->fsize);
    serialize_Message(message, data);
    
    // Send the header  
    if(send(sock, data, message->size, 0) == -1){
        perror("send"); 
        close(sock);  // Might not want to close (possibly try again?)
        exit(1); 
    }
    
    explicit_bzero(data, message->size); 
    free(data); 
    data = NULL; 
    explicit_bzero(message->data, message->jsize); 
    free(message->data); 
    message->data = NULL; 
    
    
    
    off_t offset = 0; 
    ssize_t count = st.st_size; 
    ssize_t bytes_sent; 
    size_t total_sent = 0; 


    
    
    while (count > 0){
        fd_set write_fds;
        FD_ZERO(&write_fds); 
        FD_SET(sock, &write_fds); 

        if(select(sock + 1, NULL, &write_fds, NULL, NULL) < 0){
            perror("sock select error");
            exit(1); 
        }

        // Wait until socket is writeable 
        if(FD_ISSET(sock, &write_fds)){
            bytes_sent = sendfile(sock, fd, &offset, count); 
            // bytes_sent = sendfile2(sock, fd, &offset, count); 
            if(bytes_sent == -1){
                perror("sendfile error"); 
                close(fd); 
                exit(1); 
            }
            count -= bytes_sent;
            total_sent += bytes_sent;  
            float percent = 100 * ((double)total_sent/st.st_size);
            printf("Progress: %zu/%lu (%.1f%%) bytes\n", total_sent, st.st_size, percent);
        }

    }


    printf("Sent File\n"); 

    // Close file descriptor 
    close(fd);

    
    return fhash;
    
    
    


}

// TODO: Finish Implementing this function.
void* handle_message_transfer(void *sock_ptr, void *message_ptr){

    int sock = *(int *)sock_ptr; 
    char *user_input_buffer = malloc(BUF_SIZE); 
    int user_input_size = BUF_SIZE; // Current size of user_input_buffer
    int data_length = 0; // total amount of data that has been entered
                         

    while(strncmp(user_input_buffer, "!exit", 5)){ 

        data_length = 0; 
        bzero(user_input_buffer, user_input_size);
        printf("Enter Message: ");

        while(fgets(user_input_buffer + data_length, user_input_size - data_length, stdin) != NULL){
            data_length += strlen(user_input_buffer + data_length); 
            

            // User pressed enter and is done entering data
            if(data_length > 0 && '\n' == user_input_buffer[data_length - 1]){
                user_input_buffer[data_length - 1] = '\0'; 
                break; 
            }

            if(data_length >= user_input_size - 1){
                user_input_size += BUF_SIZE; 
                user_input_buffer = realloc(user_input_buffer, user_input_size); 
                if(!user_input_buffer){
                    perror("realloc user_input_buffer failed"); 
                    exit(EXIT_FAILURE);
                }
            }
        }
        printf("User Input: %s\n", user_input_buffer); 

    }
    // Use sendmsg() and recvmsg()? 
    
}


// TODO: Implement this function.
void* handle_test(void *a, void* b){
    printf("TODO: Implement handle_test\n"); 

}


OperationFunc getOperation(uint64_t op){
    OperationFunc *func; 
    switch(op){
        case TEST_OPERATION:
            printf("Test Operation\n"); 
            // func = malloc(sizeof(handle_test));
            // return handle_test;
            return NULL;
            break; // Technically don't need a break after a return but just in case. 
        case FILE_TRANSFER:
            // printf("File Transfer\n");
            // func = malloc(sizeof(handle_file_transfer)); 
            return handle_file_transfer;
            break;  
        case MESSAGE:
            // printf("Message\n"); 
            printf("Invalid operation\n");
            // func = malloc(sizeof(handle_message_transfer)); 
            // return handle_message_transfer;
            return NULL;
            // return func;
            break;
        default: 
            printf("Invalid operation\n");
            return NULL;
            break;

    }
    
}

void* connect_to_server(const char *address, const char* port){
    /*
    * gai - get address info (holds the result from the function call and is used for error handling)
    * sfd - Holds socket information (result from socket())
    * numbytes - number of bytes read from server
    * buf - 
    * len - 
    * nread - 
    * result - holds the result from getaddrinfo()
    * rp - used as an iterator when iterating through address structures
    */
    int  gai, numbytes; 
    char buf[BUF_SIZE]; 
    size_t len; 
    ssize_t nread; 
    struct addrinfo hints; 
    struct addrinfo *result, *rp; 
    

    int *sfd = malloc(sizeof(int)); 


    // Establishing the Socket connection

    // Obtain address(es) matching host/port. 
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // Socket Stream 
    hints.ai_flags = 0; 
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol
                            

    

    /* 
     * getaddrinfo() returns a list of address structures. 
     Try each address until we successfully connect(2). 
     If socket (2) (or connect(2)) faills, we close the socket
     and try the next address. 
    */
    // gai = getaddrinfo(argv[1], argv[2], &hints, &result); 
    gai = getaddrinfo(address, port, &hints, &result); 

    if (gai != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        exit(EXIT_FAILURE);
    }
    
    for (rp = result; rp != NULL; rp = rp->ai_next){
        *sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); 
        if(*sfd == -1)
            continue; // 
        if(connect(*sfd, rp->ai_addr, rp->ai_addrlen) != -1){
            printf("socket connected\n");
            break; // Success
        }
        close(*sfd); 
    }
    
    freeaddrinfo(result); // No longer needed as we found an address structure

    if (rp == NULL){
        fprintf(stderr, "Could not connect\n"); 
        exit(EXIT_FAILURE);
    }
    
    return sfd; 
}



int main(int argc, char *argv[]){

    if(argc != 3){
        fprintf(stderr, "Usage: %s host port \n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Address: %s\n", argv[1]); 
    printf("Port: %s\n", argv[2]); 
    

    int *sock_ptr = (int*)connect_to_server(argv[1], argv[2]);
    if(sock_ptr == NULL){
        fprintf(stderr, "Could not connect\n"); 
        exit(EXIT_FAILURE);
    }

    int sock = *sock_ptr;  



    // Start of connection handling 
    size_t user_input_size = BUF_SIZE / 2;  // Size of the user input buffer (if doing user input)
    
    // The message format for sending messages
    struct Message *cmess;  
    
    char* buffer = malloc(BUF_SIZE);
    
    unsigned char test_hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    // Main loop where we communicate with the server 
    while(1){
        // FREE
        bzero(buffer, BUF_SIZE);
        cmess = malloc(sizeof(struct Message));
        if(!cmess){
            perror("cmess malloc");
            exit(EXIT_FAILURE);
        }
        // Command handling 
        printf("Enter Command: "); 
        scanf("%u", &cmess->operation);
        
        // Clearing the input buffer
        while((getchar()) != '\n' && !feof(stdin)); 
        
        
        if(cmess->operation == 0){
            printf("Exiting \n");
            break;
        }

        OperationFunc selectedOP = getOperation(cmess->operation);
        
        if(selectedOP == NULL){
            printf("Error: Invalid Command\n"); 
        }else{
            // do the operation
            unsigned char *fhash = (unsigned char *)selectedOP(sock_ptr, cmess);
            printf("MD5 Hash: ");
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                printf("%02"PRIx8, fhash[i]); // %02x for lowercase hex, %02X for uppercase
            }
            printf("\n");

            // free(selectedOP);
            check_server_socket(sock, 10);
            ssize_t numbytes = recv(sock, buffer, BUF_SIZE, 0);
            if(numbytes == -1){
                perror("recv");
                close(sock); 
                break;
            }
            printf("Received MD5 Hash: ");
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                printf("%02"PRIx8, buffer[i]); // %02x for lowercase hex, %02X for uppercase
            }
            printf("\n");

            if(!memcmp(fhash, buffer, MD5_DIGEST_LENGTH)){
                printf("File Integrity Check Passed!\n");
            }else if(!memcmp(buffer, test_hash, MD5_DIGEST_LENGTH)){
                printf("WARNING: Test Hash Received. File was received but may not have been written to disk!\n"); 
            }else{
                printf("ERROR: File Integrity Check Failed!\n");
            }
            bzero(cmess, sizeof(struct Message)); 
            free(cmess);
            cmess = NULL;
            free(fhash);
        }

        // if(!strncmp(user_input, "!exit", 5)){
        //     printf("Exit command detected \n");
        //     break;
        // }

        

        // Handle 

        
    }
    free(sock_ptr); // Free the ptr from connect_to_server return value;  
    bzero(buffer, BUF_SIZE); 
    free(buffer); 
    buffer = NULL; 






    // End of connection handling 
    printf("Done! \n");

    return 0; 
}