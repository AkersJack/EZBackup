#include "libarch.h"
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>


/*

    Compile: 
    gcc -g -D TEST_MAIN libarch.c -o libarch -l larchive -l libarch.h


*/



// Create an archive with files and stream to server  

/*
 * files -> A list of strings to file locations 
 * options -> What format and options to use for the archive (0 is defaula
 * sock
*/ 

// Custom write callback for streaming over socket
int archive_stream_files(const char **files, int sock, char* options, int num_files){ 
    struct archive *a; 
    struct archive_entry *entry; 
    // char buff[8192]; 
    char buff[131072]; // 128KB
    ssize_t bytes_read; 

    // Create new archive writer 
    a = archive_write_new();
    if(!a){
        perror("Error archive_write_new"); 
    }
    // Other options are available 
    if(archive_write_set_options(a, "format=tar, filter=zstd, compression-level=10") != ARCHIVE_OK){
        fprintf(stderr, "%s\n", archive_error_string(a)); 
        archive_write_free(a); 
        return 1; 
    }

    
    // archive_write_open(a, &sock, NULL, (archive_write_callback *)send, NULL); 
    if(archive_write_open_fd(a, sock) != ARCHIVE_OK){
        fprintf(stderr, "Failed to open archive: %s\n", archive_error_string(a));
        return -1; 
    }
    

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
        archive_write_header(a, entry); 

        // Stream file content 
        while((bytes_read = fread(buff, 1, sizeof(buff), file)) > 0){
            archive_write_data(a, buff, bytes_read); 
        }
        
        // off_t offset = 0; 
        // ssize_t sent = sendfile(socket, file_fd, &offset, st.st_size);
        
        // Cleanup 
        fclose(file); 
        archive_entry_free(entry); 

    }


    // Finish archive
    archive_write_close(a);
    archive_write_free(a); 
    return 0; 
    
    
}




#ifdef TEST_MAIN
int main(int argc, char *argv[]){ 

    // if (argc != 2){
    //     fprintf(stderr, "Usage: %s port \n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }
    
    return 0;
}

#endif