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

#if defined(__APPLE__)
    #define explicit_bzero(ptr, size)   memset_s(ptr, size, 0, size)
#endif



#include <errno.h> 
#include <string.h> 
#include <cjson/cJSON.h>
#include <stdlib.h> 
#include <stdio.h> 
#include <fcntl.h> 
#include <sys/socket.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <archive.h> 
#include <archive_entry.h>

/* 

Compile with hash gen: 
gcc -g client_new.c -o client -l cjson -l ssl -l crypto 


Compile with libarch.h:

gcc -c libarch.c -o libarch.o

gcc -c client_new.c -o client_new.o

gcc libarch.o client_new.o -o client_new -lcjson -lssl -lcrypto -larchive


Full command: 

gcc -c libarch.c -o libarch.o && gcc -c -D TEST_CLIENT client_new.c -o client_new.o && gcc libarch.o client_new.o -o client_new -lcjson -lssl -lcrypto -larchive





*/


// Default buffer size 
#define BUF_SIZE 1024 
#define MAX_FNAME_LENGTH 4096 // Maximum length a filename can be 
#define MAX_FILES 10 // Default max for number of files to transfer at once (can be increased or decreased)


// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void* , void*); 



struct Message{
        uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
        uint32_t size; // Total size of the payload/message 
        uint32_t dsize; // Data size (size of data associated with this packet)
        uint32_t jsize; // Size of json file (if included)
        uint64_t total_transfered; // Total amount of data transfered (can be NULL)
        char *data; // JSON data but can be NULL for no data
};


struct BasicHeader{
    uint32_t size; // Size incomming 
    uint32_t eof; // End of file? (0 for no 1 for yes) 
};

typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 

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

// Takes a buffer that will be sent and generates a hash (ensures all data received is good)
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




/*
 * There is probably a better way to do this 
*/
int serialize_Message(struct Message *s, char *buffer){
    unsigned int offset = 0; 
    
    // serialize all numbers 
    
    // operation 
    uint32_t operation = htonl(s->operation); 
    memcpy(buffer + offset, &operation, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);
    
    // size
    uint32_t size = htonl(s->size); 
    memcpy(buffer + offset, &size, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);

    // dsize
    uint32_t dsize = htonl(s->dsize); 
    memcpy(buffer + offset, &dsize, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);

    // jsize
    uint32_t jsize = htonl(s->jsize); 
    memcpy(buffer + offset, &jsize, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);
    
    // Split 
    uint64_s sv = split_u64(s->total_transfered); 

    uint32_t fsize_lower = htonl(sv.lower); 
    memcpy(buffer + offset, &fsize_lower, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);

    uint32_t fsize_upper = htonl(sv.upper); 
    memcpy(buffer + offset, &fsize_upper, sizeof(uint32_t)); 
    offset += sizeof(uint32_t);
    
    // memcmp(buffer + offset, s->data, s->jsize);

    return 0;  
}

// Custom implementation of sendfile()
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

// Already have this in recurse.c so can reuse it
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

// This frees the items
void free_user_input_files(char **user_inputs){

}


// Holds file array and length of the file array
struct fileContainer{
    char **files; 
    unsigned int num_files; 
};
// Need to free the buffer (returned value) Gets the user input for the file to copy
struct fileContainer get_user_input_files(){
        // Free user_input buffer 
        
        char **files = malloc(sizeof(char *) * MAX_FILES); 
        char *user_input_buffer = malloc(BUF_SIZE); 
        int user_input_size = BUF_SIZE; // Current size of the user_input_buffer
        int data_length = 0; // total amount of data that has been entered
        int fd; // File descriptor for checking if file exists
        unsigned int num_files = 0; // 
        unsigned int num_files_max = MAX_FILES;
        unsigned int num_lines; // Number of lines written to terminal 

        while(1){
            bzero(user_input_buffer, user_input_size); 
            printf("Enter File Location: ");
            // Get user input
            while (fgets(user_input_buffer + data_length, user_input_size - data_length, stdin) != NULL){
                data_length += strlen(user_input_buffer + data_length);

                // User pressed enter and is done entering data
                if(data_length > 0 && '\n' == user_input_buffer[data_length - 1]){
                    // user_input_buffer[data_length - 1] = '\0'; 
                    user_input_buffer[data_length - 1] = '\0'; 
                    break; 
                }
                if (data_length >= user_input_size - 1)
                {
                    user_input_size += BUF_SIZE;
                    user_input_buffer = realloc(user_input_buffer, user_input_size);
                    if (!user_input_buffer)
                    {
                        perror("realloc user_input_buffer failed");
                        exit(EXIT_FAILURE);
                    }
                }
            }

                // If the user input is correct tryu to open the file so we can ensure it exists

                if (!strncmp(user_input_buffer, "exit", 4)){
                    break;
                }
                fd = open(user_input_buffer, O_RDONLY);
                if (fd < 0){
                    perror("Failed to open file");
                    data_length = 0;
                    continue;
                }
                files[num_files] = user_input_buffer;
                num_files++;
                if (num_files >= (num_files_max - 1)){
                    num_files_max += 10; // Going to add 10 more files at a time
                    files = realloc(files, sizeof(char *) * num_files_max);
                }
                // Need to create a new pointer so I don't overwrite data from the previous pointer
                user_input_buffer = malloc(BUF_SIZE);
                user_input_size = BUF_SIZE; 
                data_length = 0; 

                close(fd);
        }


        
        struct fileContainer fc; 
        fc.files = files; 
        fc.num_files = num_files;

        return fc;        
        
}
int sendBaseHeader(int sock, uint32_t length, uint32_t eof){
    char baseBuff[8]; 
    uint32_t size = htonl(length); // Length of the data to be sent 
    eof = htonl(eof);  // End of file ? 
    
    memcpy(baseBuff, &size, 4); 
    memcpy(baseBuff + 4, &eof, 4); 
    
    size_t bytes_sent; 
    
    // Should check this TODO: error checking
    bytes_sent = send(sock, baseBuff, 8, 0);
    
    return 1; 

    
}

ssize_t socket_write_cb(struct archive *, void *client_data, const void *buff, size_t length){
    int sock = *((int *)client_data);
    
    ssize_t bytes_sent; 

    
    // Send something for how much data to expect
    
    sendBaseHeader(sock, length, 0); 
    
    // TODO: Error checking
    bytes_sent = send(sock, buff, length, 0); 
    
    // printf("Socket callback - Attempted to send %zu bytes, Actually sent: %zd\n", length, bytes_sent);
    if(bytes_sent < 0){
        perror("Socket callback send error");
    }
    
    return bytes_sent; 
}


// Stream files using libarchive 
int archive_stream_files(const char **files, int sock, struct Message *msg, int num_files){ 
    struct archive *a; 
    struct archive_entry *entry; 
    // char buff[8192]; 
    char buff[131072]; // 128KB
    ssize_t bytes_read; 
    
    msg->jsize = 0; 
    msg->total_transfered = 0; 
    msg->size = (sizeof(uint32_t) * 4) + sizeof(uint64_t);
    
    char *header_buff = malloc(msg->size); 
    ssize_t header_bytes_sent = 0;
    
    // char *archive_buffer = malloc(102400);
    size_t archive_buffer_size = 102400; 
    size_t archive_buffer_used = 0; 



    // Create new archive writer 
    a = archive_write_new();
    printf("Current Block size: %d\n", archive_write_get_bytes_per_block(a));
    printf("Current Last Block size: %d\n ", archive_write_get_bytes_in_last_block(a));
    // archive_write_set_bytes_per_block(a, 1024);
    if(!a){
        perror("Error archive_write_new"); 
    }
    // archive_write_set_bytes_per_block(a, 0);
    // Other options are available 
    // Try this maybe use POSIX tar if not work
    if(archive_write_set_format_gnutar(a) != ARCHIVE_OK){
        fprintf(stderr, "%s\n", archive_error_string(a)); 
        archive_write_free(a); 
        return 1;  
    }
    archive_write_add_filter_zstd(a);
    if(archive_write_set_filter_option(a,"zstd", "compression-level", "1") != ARCHIVE_OK){
        fprintf(stderr, "%s\n", archive_error_string(a)); 
        archive_write_free(a); 
        return 1;  
    }
    
    // if(archive_write_set_options(a,"format=gnutar,Filter=zstd,compression-level=10") != ARCHIVE_OK){
    //     fprintf(stderr, "%s\n", archive_error_string(a)); 
    //     archive_write_free(a); 
    //     return 1; 
    // }

    
    // if(archive_write_open(a, &sock, NULL, (archive_write_callback *)send, NULL) != ARCHIVE_OK){
    // archive_write_open_memory()
    // archive_write_open_fd()
    if(archive_write_open(a, &sock, NULL, socket_write_cb, NULL) != ARCHIVE_OK){
    // if(archive_write_open_memory(a, archive_buffer, 102400, &archive_buffer_used) != ARCHIVE_OK){
    // if(archive_write_open_fd(a, sock) != ARCHIVE_OK){
        fprintf(stderr, "Failed to open archive: %s\n", archive_error_string(a));
        return -1; 
    }
            
            
            
    // int offset = 0; 
    msg->dsize = 10240;
    serialize_Message(msg, header_buff); 

    
    

    // Send the big header
    if((header_bytes_sent = send(sock, header_buff, msg->size, 0)) == -1){
        perror("send"); 
        close(sock);  // Might not want to close (possibly try again)
        exit(1); 
    } 
    printf("Header bytes_sent: %ld\n", header_bytes_sent);
    


    for (int i = 0; i < num_files; i++){
        FILE *file = fopen(files[i], "rb"); 
        if (!file){
            fprintf(stderr, "Cannot open file: %s\n", files[i]); 
            continue; 
        }

        entry = archive_entry_new();
        // A lot of different options for archive_entry_set
        archive_entry_set_pathname(entry, files[i]); 
        
        // Get file size
        fseek(file, 0, SEEK_END); // Move pointer to end of file
        archive_entry_set_size(entry, ftell(file)); // Get fsize and set that size
        rewind(file); // Set the pointer back to the beginning
        
        // AE_IFDIR for directory, AE_IFLINK for symbolic link, etc.
        archive_entry_set_filetype(entry, AE_IFREG);
        
        archive_entry_set_perm(entry, 0644); 
        

        // Write header 
        if(archive_write_header(a, entry) != ARCHIVE_OK){
            fprintf(stderr, "Writing archive header failed%s\n", archive_error_string(a));
            exit(1);
        } 

        // archive_write_set_bytes_per_block() // to adjust blocksize 
        // Stream file content 
        while((bytes_read = fread(buff, 1, sizeof(buff), file)) > 0){
            // printf("Bytes read: %lu\n", bytes_read);

            
            
            // Write the data to an internal buffer
            la_ssize_t bytes_sent = archive_write_data(a, buff, bytes_read); 
            // printf("Archive buffer used: %lu\n", archive_buffer_used);
            if(bytes_sent < 0){ // Apparently sometimes it can return zero and it won't be an error 
                fprintf(stderr, "Error: failed to write data! %s\n", archive_error_string(a)); 
                exit(1); 
            }
            // printf("Bytes sent: %ld\n", bytes_sent);
            
            
            msg->total_transfered += (uint64_t)bytes_sent;
            bzero(header_buff, msg->size); 

            printf("total transfered: %lu\n", msg->total_transfered);
        }
        
        // Cleanup 
        fclose(file); 
        archive_entry_free(entry); 
        free(header_buff);  
        sendBaseHeader(sock, 0, 1); // Let the server know the end of the file has been sent
        printf("Sent File!\n"); 

    }


    // Finish archive
    archive_write_close(a);
    // printf("archive buffer used: %lu\n", archive_buffer_used);
    archive_write_free(a); 
    // free(archive_buffer);
    return 0; 
    
    
}


    

void* handle_file_transfer(void *sock_ptr, void *message_ptr){
   int sock = *(int *)sock_ptr; 
    struct Message *message = (struct Message *)message_ptr; 
    // Free this
    struct fileContainer fc = get_user_input_files(); // Probably use another function here in production
    for (int i = 0; i < fc.num_files; i++){
        printf("%s\n", fc.files[i]);
    }


    archive_stream_files((const char**)fc.files, sock, message, fc.num_files);


    

    


        
    //    cJSON *jsonObject = createJSON(user_input); 
    //    char *json_string = cJSON_Print(jsonObject); 
    //    message->jsize = strlen(json_string); 
    // message->jsize = 0; 
    
       
       
    //    // Compress and send
       

    //    free(user_input); 
       
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




#ifdef TEST_CLIENT
int main(int argc, char *argv[]){
        unsigned char test_hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
        if(argc != 3){
                fprintf(stderr, "Usage: %s host port \n", argv[0]);
        } 
       
        printf("Address: %s\n", argv[1]); 
        printf("Port: %s\n", argv[2]); 
       
        int *sock_ptr = (int *)connect_to_server(argv[1], argv[2]); 
        if(!sock_ptr){
                fprintf(stderr, "Could not connect\n");
        }

        int sock = *sock_ptr;

        // Start of connection handling

        
        // The message format for sending messages
        struct Message *cmess;  
    
        char* buffer = malloc(BUF_SIZE);

         
        while(1){
                // Command handling 
                bzero(buffer, BUF_SIZE);
                cmess = malloc(sizeof(struct Message));
                if(!cmess){
                    perror("cmess malloc");
                    exit(EXIT_FAILURE);
                }
                printf("Enter Command: ");
                scanf("%u", &cmess->operation); 
                
                // Clearing the input buffer
                while((getchar()) != '\n' && !feof(stdin)); 
                
                if(cmess->operation == 0){
                        printf("Exiting \n"); 
                        break;
                }
                
                OperationFunc selectedOP = getOperation(cmess->operation);
                if(!selectedOP){
                        fprintf(stderr, "Error: Invalid Command\n"); 
                        continue;
                }
                unsigned char *fhash = (unsigned char *)selectedOP(sock_ptr, cmess);
                printf("MD5 Hash: "); 
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++){
                        printf("%02"PRIx8, fhash[i]);  // %02x for lowercase hex, %02X for uppercase
                }
                printf("\n");

                // check_server_socket(sock, 10); 
                ssize_t numbytes = recv(sock, buffer, BUF_SIZE, 0); 
                if(numbytes == -1){
                        perror("recv"); 
                        close(sock); 
                        break;
                }
                printf("Received MD5 Hash: ");
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++){
                        printf("%02"PRIx8, buffer[i]);  // %02x for lowercase hex, %02X for uppercase
                }
                printf("\n");
                

                if(!memcmp(fhash, buffer, MD5_DIGEST_LENGTH)){
                        printf("File Integrity check Passed!\n"); 
                }else if(!memcmp(buffer, test_hash, MD5_DIGEST_LENGTH)){ 
                        printf("WARNING: Test Hash Received. File was received but may not have been written to disk!\n"); 
                }else{
                     ("ERROR: File Integrity Check Failed!\n");
                }

                bzero(cmess, sizeof(struct Message)); 
                free(cmess); 
                cmess = NULL; 
                free(fhash);

                
        }
        
        free(sock_ptr); 
        bzero(buffer, BUF_SIZE); 
        free(buffer);
        buffer = NULL; 


        
        printf("Done! \n"); 

       return 0;
}
#endif