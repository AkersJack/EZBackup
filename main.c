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
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include <cjson/cJSON.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <time.h> 
#include <openssl/md5.h> 
#include <sys/types.h>
#include <netdb.h>
#include <archive.h>
#include <archive_entry.h>
#include "tools.h"
#include <ctype.h>
#include <math.h>


/* 

Compile with cjson: 
gcc -g -D TEST_MAIN client.c -o client -l cjson 

OR if we define main:
gcc -g client.c -o client -l cjson 


Compile with hash gen: 
gcc -g client.c -o client -l cjson -l ssl -l crypto

cmake --build .

*/


#define BUF_SIZE 1024
#define MAX_FILES 10

#define MAX_FNAME_LENGTH 4096 // Maximum length a filename can be 


// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void* , void*); 

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

// Contains all the possible operations
typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 

typedef struct{
    uint32_t upper;  // Upper half of a uint64_t
    uint32_t lower; // Lower half of a uint64_t
}uint64_s;

struct fileContainer{
        char **files; 
        unsigned int num_files; 

};

typedef struct{
        char units[3];
        double size; 

}sizeObject;

sizeObject sizeFormat(long double num){
        sizeObject sObj = {"", 0};
        char units[][3] = {"B", "KB", "MB", "GB", "TB", "PB"}; 
        long double sizes[] = {1, 1024, pow(1024, 2), pow(1024, 3), pow(1024, 4), pow(1024, 5)}; 
        for(int i = 1; i < sizeof(sizes); i++){
                if (sizes[i] > num){
                        sObj.size = num / sizes[i - 1];
                        strncpy(sObj.units, units[i - 1], 2);
                        sObj.units[sizeof(sObj.units) - 1] = '\0';
                        break;
                }
        }
        
        return sObj; 
}

struct fileContainer get_user_input_files(){
        char **files = malloc(sizeof(char *) * MAX_FILES);
        char *user_input_buffer = malloc(1024); 
        int user_input_size = 1024; 
        int data_length = 0; 
        int fd; 
        unsigned int num_files = 0; 
        unsigned int num_files_max = MAX_FILES; 
        int end_index; 
        struct stat st; 
        



        while(1){
                bzero(user_input_buffer, user_input_size); 
                printf("Enter File Location (\"exit\" to compress and archive files): "); 
                // Get user input
                while(fgets(user_input_buffer + data_length, user_input_size - data_length, stdin) != NULL){
                        data_length += strlen(user_input_buffer + data_length);

                        end_index = data_length - 1; 
                        // User pressed enter and is done entering data
                        if(data_length > 0 && '\n' == user_input_buffer[data_length - 1]){

                                // Remove trailing white spaces
                                while(end_index >= 0 && isspace(user_input_buffer[end_index])){
                                        end_index--;
                                }
                                
                                user_input_buffer[end_index + 1] = '\0';
                                if(user_input_buffer[0] == '\'' && user_input_buffer[strlen(user_input_buffer) - 1] == '\''){
                                        for(int i = 1; i < end_index; i++){
                                                user_input_buffer[i - 1] = user_input_buffer[i]; // Shift all characters to the left 
                                        }
                                        user_input_buffer[end_index - 1] = '\0';
                                }

                                printf("File Name: %s\n", user_input_buffer);
                                // parse_files(user_input_buffer, &parseItems);
                                // for(int j = 0; j < parseItems.size; j++){
                                //         printf("%s\n", parseItems.items[j]);
                                // }
                                break;
                        }

                        if(data_length >= user_input_size - 1){
                                user_input_size += 1024; 
                                user_input_buffer = realloc(user_input_buffer, user_input_size); 
                                if(!user_input_buffer){
                                        perror("realloc user_input_buffer failed"); 
                                        exit(EXIT_FAILURE); 
                                }
                        }
                }

                // Try to stat the file/directory to ensure that it actually exists 
                if(!strncmp(user_input_buffer, "exit", 4)){
                        break; 
                }
                if (stat(user_input_buffer, &st) != 0) {
                        fprintf(stderr, "Failed to stat input file %s\n", user_input_buffer);
                        data_length = 0; 
                        continue; 
                }

                // fd = open(user_input_buffer, O_RDONLY); 
                // if (fd < 0){
                //         perror("Failed to open file"); 
                //         data_length = 0; 
                //         continue; 
                // }
                
                files[num_files] = user_input_buffer; 
                num_files++; 
                if(num_files >= (num_files_max - 1)){
                        num_files_max += 10; 
                        files = realloc(files, sizeof(char *) * num_files_max); 
                        if(!files){
                                perror("realloc files failed"); 
                                exit(EXIT_FAILURE); 
                        }
                }

                user_input_buffer = malloc(1024); 
                user_input_size = 1024; 
                data_length = 0; 


                // close(fd); 

                

                
        }

        struct fileContainer fc; 
        fc.files = files; 
        fc.num_files = num_files; 
        free(user_input_buffer); 
        user_input_buffer = NULL;

        return fc;
        
}

// Free user input here
int freeUserInput(struct fileContainer *fc){
        for(int i = 0; i < fc->num_files; i++){
                free(fc->files[i]);
                fc->files[i] = NULL;
        }
        free(fc->files);
        fc->files = NULL;
        
        return 0;

}

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

struct custom_write_data{
        FILE *output_file; 
        const char *output_filename;
        uint64_t *total_written; // For compressed size
        uint64_t *total_read; // For uncompressed size 
        int sock; // For socket
};

ssize_t custom_write_cb(struct archive * a, void *client_data, const void *buffer, size_t length){
        struct custom_write_data *mydata = client_data;
        size_t written = fwrite(buffer, 1, length, mydata->output_file);
        if (written != length){
                archive_set_error(a, errno, "Write error");
                return -1;
        }
        *(mydata->total_written) += written;
        
        long double percent_comp = (((long double)*(mydata->total_written) / (long double)*(mydata->total_read))) * 100;
        
        sizeObject sizeObj_1;
        sizeObject sizeObj_2;
        sizeObj_1 = sizeFormat(((long double) *(mydata->total_written))); 
        sizeObj_2 = sizeFormat(((long double) *(mydata->total_read))); 


        // printf("Total Written: %lu\t Total Read: %lu\t Compressed Size: %.2Lf%% of original\n", *(mydata->total_written), *(mydata->total_read), percent_comp);
        printf("Total Written: %.2lf %s\t Total Read: %.2lf %s\t Compressed Size: %.2Lf%% of original\n", sizeObj_1.size, sizeObj_1.units, sizeObj_2.size, sizeObj_2.units, percent_comp);
        

        return written;
}

int sendBaseHeader(int sock, uint32_t length, uint32_t eof){
    char baseBuff[8]; 
    
    // Length of the data to be sent
    uint32_t size = htonl(length); 
    
    // End of file?
    eof = htonl(eof);
    memcpy(baseBuff, &size, 4); 
    memcpy(baseBuff + 4, &eof, 4); 
    
    size_t bytes_sent; 

    // Should check this TODO: error checking
    bytes_sent = send(sock, baseBuff, 8, 0); 

    return 0; 
}

// This one is for streaming over a socket
ssize_t custom_write_cb2(struct archive * a, void *client_data, const void *buffer, size_t length){
        struct custom_write_data *mydata = client_data;
        
        
        // size_t written = fwrite(buffer, 1, length, mydata->output_file);
        
        sendBaseHeader(mydata->sock, length, 0);

        // TODO: Error checking
        size_t written = send(mydata->sock, buffer, length, 0);
        if(written < 0){
            perror("Socket callback send error");
        }
        // if (written != length){
        //         archive_set_error(a, errno, "Write error");
        //         return -1;
        // }
        *(mydata->total_written) += written;
        
        long double percent_comp = (((long double)*(mydata->total_written) / (long double)*(mydata->total_read))) * 100;
        
        sizeObject sizeObj_1;
        sizeObject sizeObj_2;
        sizeObj_1 = sizeFormat(((long double) *(mydata->total_written))); 
        sizeObj_2 = sizeFormat(((long double) *(mydata->total_read))); 


        // printf("Total Written: %lu\t Total Read: %lu\t Compressed Size: %.2Lf%% of original\n", *(mydata->total_written), *(mydata->total_read), percent_comp);
        printf("Total Written: %.2lf %s\t Total Read: %.2lf %s\t Compressed Size: %.2Lf%% of original\n", sizeObj_1.size, sizeObj_1.units, sizeObj_2.size, sizeObj_2.units, percent_comp);
        

        return written;
}

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
    
    // Fsize
    // uint32_t fsize = htonl(s->fsize); 
    // memcpy(buffer + offset, &fsize, sizeof(uint32_t)); 
    // offset += sizeof(uint32_t);


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



int stream_archive(struct fileContainer *fc, int socket, struct Message *msg){
        struct archive *a; 
        struct archive *dir_a; 
        struct archive_entry *entry; 
        char buff[131072]; 
        // char buff[8192]; 
        int len; 
        int fd; 
        struct stat st; 
        int r; 
        uint64_t total_written = 0; 
        uint64_t total_read = 0;
        
        msg->size = (sizeof(struct Message)); 
        msg->total_transfered = 0; 
        msg->jsize = 0;
        msg->dsize = 10240;

        char *header_buff = malloc(msg->size);

        char output_filename[] = "./new_test.tar.zst";

        size_t header_bytes_sent = 0;

        serialize_Message(msg, header_buff);

        // Send the big header
        if ((header_bytes_sent = send(socket, header_buff, msg->size, 0)) == -1) {
                perror("send");
                close(socket);  // Might not want to close (possibly try again)
                free(header_buff);
                exit(1);
        }
        
        free(header_buff);
        printf("Header bytes_sent: %ld\n", header_bytes_sent);

        // char output_filename[] = "/mnt/E66294026293D5A1/test_Jack_Windows_Backup.tar.zst"; 
        // char output_filename[] = "/mnt/E66294026293D5A1/testBackup.tar.zst"; 
        // char output_filename[] = "../testOutput_new.tar.zst"; 
        
        // Create a new archive object for reading directories 
        if((dir_a = archive_read_disk_new()) == NULL){
                fprintf(stderr, "Failed to initialize archive structure: %s\n", archive_error_string(dir_a));
                return 1; 
        }
        
        //Configure archive objects 
        archive_read_disk_set_standard_lookup(dir_a); 
        archive_read_disk_set_symlink_physical(dir_a);


        // Init archive structure 
        if((a = archive_write_new()) == NULL){
                fprintf(stderr, "Failed to initialize archive structure: %s\n", archive_error_string(a));
                return 1;
        }
        
        
        if(archive_write_set_format_gnutar(a) != ARCHIVE_OK){
                fprintf(stderr, "Error setting tar format: %s\n", archive_error_string(a));
                return 1;
        }


        if(archive_write_add_filter_zstd(a) != ARCHIVE_OK){
                fprintf(stderr, "Error setting zstd compression: %s\n", archive_error_string(a));
                return 1;
        }

        if(archive_write_set_filter_option(a, "zstd", "compression-level", "20") != ARCHIVE_OK){
                fprintf(stderr, "Error setting zstd compression level: %s\n", archive_error_string(a));
                return 1;
        }

        if (archive_write_set_filter_option(a, "zstd", "threads", "0") != ARCHIVE_OK) {
                fprintf(stderr, "Error setting zstd threads: %s\n", archive_error_string(a));
                return 1;
        }

        archive_write_set_bytes_per_block(a, 10240);
        archive_write_set_bytes_in_last_block(a, 1);
        // Setup custom write callback
        struct custom_write_data mydata;
        mydata.total_read = &total_read;
        mydata.total_written = &total_written; 
        mydata.output_file = fopen(output_filename, "wb");
        mydata.sock = socket;

        if (mydata.output_file == NULL) {
                fprintf(stderr, "Failed to open output file %s\n", output_filename);
                archive_write_free(a);
                return 1;
        }
        mydata.output_filename = output_filename;

        // Set the callback
        // archive_write_open(a, &mydata, NULL, custom_write_cb, NULL);
        archive_write_open(a, &mydata, NULL, custom_write_cb2, NULL);
        char *base_name; 
        /* Archive and compress each file using libachive */
        for (int i = 0; i < fc->num_files; i++) {
                entry = archive_entry_new();
                r = archive_read_disk_open(dir_a, fc->files[i]);
                if (r != ARCHIVE_OK) {
                        fprintf(stderr, "Failed to open directory: %s\n", archive_error_string(dir_a));
                        archive_read_free(dir_a);
                        return -1;
                }

                while(archive_read_next_header(dir_a, &entry) == ARCHIVE_OK){
                        const char *current_path = archive_entry_pathname(entry);
                        const struct stat *sta = archive_entry_stat(entry);
                        char type = '?';
                        
                        // Determine entry type
                        if (S_ISREG(sta->st_mode)) {
                                type = '-';
                                archive_entry_set_filetype(entry, AE_IFREG);
                        } else if (S_ISDIR(sta->st_mode)) {
                                type = 'd';
                                archive_entry_set_filetype(entry, AE_IFDIR);
                        } else if (S_ISLNK(sta->st_mode)) {
                                type = 'l';
                        } else if (S_ISBLK(sta->st_mode)) {
                                type = 'b';
                        } else if (S_ISCHR(sta->st_mode)) {
                                type = 'c';
                        } else if (S_ISFIFO(sta->st_mode)) {
                                type = 'p';
                        } else if (S_ISSOCK(sta->st_mode)) {
                                type = 's';
                        }
                        archive_entry_set_size(entry, sta->st_size);
                        printf("%c %10lld %s\n", type, (long long)sta->st_size, current_path);
                        
                        
                        archive_write_header(a, entry);
                        if(type == '-'){
                                // Copy file data
                                // fd = open(fc->files[i], O_RDONLY);
                                fd = open(current_path, O_RDONLY);
                                if (fd < 0) {
                                        fprintf(stderr, "Failed to open input file %s\n", fc->files[0]);
                                        archive_entry_free(entry);
                                        archive_write_close(a);
                                        archive_write_free(a);
                                        fclose(mydata.output_file);
                                        return 1;
                                }

                                // Write file content
                                while ((len = read(fd, buff, sizeof(buff))) > 0) {
                                        r = archive_write_data(a, buff, len);
                                        if (r < 0) {
                                                fprintf(stderr, "Error writing data %s\n", archive_error_string(a));
                                                close(fd);
                                                archive_entry_free(entry);
                                                archive_write_close(a);
                                                archive_write_free(a);
                                                fclose(mydata.output_file);
                                                return 1;
                                        }
                                        total_read += len;
                                }

                        }

                        // If it's a directory descend into it
                        // if (S_ISDIR(sta->st_mode)) {
                        if (archive_read_disk_descend(dir_a) != ARCHIVE_OK) {
                                fprintf(stderr, "Error descending into disk: %s\n", archive_error_string(dir_a));
                                close(fd);
                                archive_entry_free(entry);
                                archive_write_close(a);
                                archive_write_free(a);
                                fclose(mydata.output_file);
                                archive_read_close(dir_a);
                                archive_read_free(dir_a);
                                return 1;
                        }
                        // }
                }

                archive_read_close(dir_a);
        }
        archive_read_free(dir_a);
        

        // Cleanup
        archive_write_close(a);
        archive_write_free(a);
        fclose(mydata.output_file);

        printf("Successfully created compressed archive: %s\n", output_filename);
        sendBaseHeader(socket, 0, 1234567890); // Let the server know the end of the file has been sent

        return 0;
}


// Handle the file transfer process
void* handle_file_transfer(void *sock_ptr, void* message_ptr){
    int sock = *(int *) sock_ptr; 
    struct Message *message = (struct Message *)message_ptr;
    
    struct fileContainer fc = get_user_input_files(); 
    
    for(int i = 0; i < fc.num_files; i++){
        printf("%s\n", fc.files[i]); 
    }
    
    message->size = 10240;
    
    stream_archive(&fc, sock, message);


    

    return 0; 

    
    
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
            printf("File Transfer\n");
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


int serverLoop(int sock){
    char *buffer = malloc(BUF_SIZE); 
    
    // Size of the user input buffer (if doing user input)
    size_t user_input_size = BUF_SIZE / 2; 

    // The message format for sending messages
    struct Message *cmess; 
    
    
    while(1){
        bzero(buffer, BUF_SIZE); ;
        cmess = malloc(sizeof(struct Message));
        if (!cmess) {
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

        if(selectedOP == NULL){
            printf("Error: Invalid Command\n"); 
        }else{
            // Do operation
            unsigned char *fhash = (unsigned char *)selectedOP(&sock, cmess);
            
            // ssize_t numbytes = recv(sock, buffer, BUF_SIZE, 0);
            // if(numbytes == -1){
            //     perror("recv");
            //     close(sock); 
            //     break;
            // }
            bzero(cmess, sizeof(struct Message)); 
            free(cmess);
            cmess = NULL;
            
        }
    }

    bzero(buffer, BUF_SIZE);
    free(buffer); 
    buffer = NULL;


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

    serverLoop(sock); 

    return 0;
}
