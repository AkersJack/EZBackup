// #include "client.h"
// #include <fcntl.h>
// #include <stdlib.h> 
// #include <stdio.h>
// #include <errno.h> 
// #include <linux/limits.h>
// #include <string.h> 
// #include <pthread.h> 
// #include <stdbool.h>
// #include <sys/socket.h> 
// #include <netdb.h>
// #include <unistd.h>
// #include <unistd.h>
// #include <stdint.h>
// #include <arpa/inet.h> 
// #include <cjson/cJSON.h>
// #include <sys/stat.h>
// #include <sys/ioctl.h>
// #include <sys/select.h>
// #include <time.h> 
// #include <openssl/md5.h> 


#include "client.h" 
#include "tools.h" /* General tools */
#include "database.h" /* Database to keep track of files */
#include "config.h" /* To read config file and other config operations */
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
#define MAX_FILES 10

#define MAX_FNAME_LENGTH 4096 // Maximum length a filename can be 



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


/* 
 * 0 = success
 * -1 = getaddrinfo() error
 *  1 = failed to connect error
*/
int initClient(const char *address, const char *port, int *sock){
    int gai, numbytes, sfd; 
    
    char buf[BUF_SIZE]; 
    size_t len; 
    ssize_t nread; 
    struct addrinfo hints; 
    struct addrinfo *result, *rp; 
    
    bzero(&hints, sizeof(hints)); 
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // Socket Stream 
    hints.ai_flags = 0; 
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol
                                     //

    /*
        getaddrinfo() returns a list of address structures.
        Try each address until we successfully bind(2).
        If socket(2) (or bind(2)) fails, we close the socket
        and try the next address.
    */
    
    // 0 on success
    gai = getaddrinfo(address, port, &hints, &result);
    if(gai != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai)); 
        return -1;
    }
    
    for (rp = result; rp != NULL; rp = rp->ai_next){
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); 
        if(sfd == -1)
            continue; 
                      
        if(connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1){
            printf("socket connected\n");
            break; // Success
        }
        close(sfd); 
    }
    

    freeaddrinfo(result); // No longer needed as we found an address structure
    
    if (rp == NULL){
        perror("Could not connect"); 
        return 1;
    }
    
    *sock = sfd; 


    return 0; 
}
ssize_t custom_write_cb2(struct archive *a, void *client_data, const void *buffer, size_t length){
    return 0;
}


int stream_archive(struct fileContainer *fc, int socket){
        struct archive *a, *dir_a; 
        struct archive_entry *entry; 
        char buff[131072] = {0}; 
        int len, fd, r;
        struct stat st; 
        uint64_t total_written = 0; 
        uint64_t total_read = 0; 

        char output_filename[] = "./new_test.tar.zst";
        char output_tablename[] = "./new_test.db";
        char database_name[] = "database.db";

        sqlite3 *db;


        init_Database(&db, database_name);

        // Returns 1 if the table already exists
        int err = createTableData(db, output_tablename);
        if (err == 1) {
                printf("Need to rename the table\n");
                sqlite3_close(db);
        } else {
                sqlite3_close(db);
        }

        // Create a new archive object for reading directories
        if ((dir_a = archive_read_disk_new()) == NULL) {
                fprintf(stderr, "Failed to initialize archive structure: %s\n", archive_error_string(dir_a));
                return 1;
        }

        // Configure archive objects
        archive_read_disk_set_standard_lookup(dir_a);
        archive_read_disk_set_symlink_physical(dir_a);

        // Init archive structure
        if ((a = archive_write_new()) == NULL) {
                fprintf(stderr, "Failed to initialize archive structure: %s\n", archive_error_string(a));
                return 1;
        }

        if (archive_write_set_format_gnutar(a) != ARCHIVE_OK) {
                fprintf(stderr, "Error setting tar format: %s\n", archive_error_string(a));
                return 1;
        }

        if (archive_write_add_filter_zstd(a) != ARCHIVE_OK) {
                fprintf(stderr, "Error setting zstd compression: %s\n", archive_error_string(a));
                return 1;
        }
        // was 20
        if (archive_write_set_filter_option(a, "zstd", "compression-level", "15") != ARCHIVE_OK) {
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
        // mydata.output_file = fopen(output_filename, "wb");
        mydata.sock = socket;

        mydata.output_filename = output_filename;

        // Set the callback
        archive_write_open(a, &mydata, NULL, custom_write_cb2, NULL);

        printf("Stream archive here\n");

        char *base_name;
        // Apparently archive_read_next_header() manages the entry internally so I don't need to manually create a new one
        // entry = archive_entry_new();
        /* Archive and compress each file using libachive */
        for (int i = 0; i < fc->num_files; i++) {
                r = archive_read_disk_open(dir_a, fc->files[i]);
                if (r != ARCHIVE_OK) {
                        fprintf(stderr, "Failed to open directory: %s\n", archive_error_string(dir_a));
                        archive_read_free(dir_a);
                        return -1;
                }

                while (archive_read_next_header(dir_a, &entry) == ARCHIVE_OK) {
                        const char *current_path = archive_entry_pathname(entry);
                        const struct stat *sta = archive_entry_stat(entry);
                        char real_path[PATH_MAX];
                        char *res = realpath(current_path, real_path);
                        if (!res) {
                                perror("realpath");
                                exit(EXIT_FAILURE);
                        }

                        char type = '?';
                        // Determine entry type (Can be broken down into its own function)
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
                        if (type == '-') {
                                // Copy file data
                                // fd = open(fc->files[i], O_RDONLY);
                                fd = open(current_path, O_RDONLY);
                                if (fd < 0) {
                                        fprintf(stderr, "Failed to open input file %s\n", fc->files[0]);
                                        archive_write_free(a);
                                        // fclose(mydata.output_file);
                                        return 1;
                                }

                                // Write file content
                                while ((len = read(fd, buff, sizeof(buff))) > 0) {
                                        r = archive_write_data(a, buff, len);
                                        if (r < 0) {
                                                fprintf(stderr, "Error writing data %s\n", archive_error_string(a));
                                                close(fd);
                                                archive_write_free(a);
                                                // fclose(mydata.output_file);
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
                                archive_write_free(a);
                                // fclose(mydata.output_file);
                                archive_read_free(dir_a);
                                return 1;
                        }
                        // }
                }

                // Should only call this if you create the entry with archive_entry_new()
                // Also archive_read_next_header() automatically does this
                // archive_entry_clear(entry);

                archive_read_close(dir_a);
        }

        // Cleanup
        archive_read_free(dir_a);
        archive_write_free(a);

        printf("Successfully created compressed archive: %s\n", output_filename);
        return 0;
}





void* handle_file_transfer(void *sock_ptr){
    int sock = *(int *) sock_ptr; 
    struct fileContainer fc;  
    fc = get_user_input_files();

    for(int i = 0; i < fc.num_files; i++){
        printf("%s\n", fc.files[i]); 
    }
    

    // Read config here
    
    stream_archive(&fc, sock);
    freeFileContainer(&fc); 
}

OperationFunc getOperation(uint8_t op){
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

int clientLoop(int sock){
    u_int32_t operation; 
    while(1){
        // bzero(buffer, BUF_SIZE); 

        printf("Enter Command: "); 
        scanf("%u", &operation);
        
        // Clearing the input buffer
        while((getchar()) != '\n' && !feof(stdin)); 
        
        if(operation == 0){
            printf("Exiting \n");
            break;
        }

        OperationFunc selectedOP = getOperation(operation);

        if(selectedOP == NULL){
            printf("Error: Invalid Command\n"); 
        }else{
            selectedOP(&sock);
        }
        

    }
    



    return 0;
}


/*
 * Frees a file container/user input
*/

int freeFileContainer(struct fileContainer *fc){
    for(int i = 0; i < fc->num_files; i++){
            printf("File: %s\n", fc->files[i]);
            free(fc->files[i]);
            fc->files[i] = NULL;
    }
    free(fc->files);
    fc->files = NULL;
    
    return 0;

}