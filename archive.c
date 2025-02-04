#include <stdio.h>
#include <string.h> 
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h> 
#include "recurse.h"
#include <archive.h> 
#include <archive_entry.h>


/* 

   Reading 
   https://linux.die.net/man/3/archive_read

   
   Writing 



   Compile 
   gcc -D TEST_COPY archive.c -o  archive -larchive

    archive_read_new()
         Used for reading streaming archives and when you want to read archive files 
         - Allocates and initializes a struct archive object suitable for reading from an archive.  
            NULL is returned on error.

         - A complete description of the struct archive object can be found in the overview manual page for libarchive(3).

    
    archive_read_disk_new()
        - Used to read information about objects on disk. 
        - Can be used to read file system entries, such as files and directories 
          rather than reading from an archive file.
        
        - Allocates and initializes a struct archive object suitable for reading object 
          information from disk.


    archive_read_data() and write data() 
        - returns a count of the bytes actually read or written. 
          a value of 0 indicates the endo f the data for this entry 
          a negative value indicates an error (archive_errno() and archive_error_string() can be 
          used for more info). 
        
        General process of reading streaming archives 
        1. Create the struct object 
        2. set options
        3. Init the reader 
        4. Iterate over the archive headers and associated data 
        5. Close the archive and release all resources. 


    archive_read_disk_set_symlink_physical()
        Allows you to specify that symbolic links should be treated as physical links 
        When set this will read the symlink itself rather than following it to the target file or directory

    archive_read_disk_set_symlink_logical()
        This is used to dereference symlinks
        This means that instead of reading the symlink itself, it reads the properties of the 
        file or directory that the symlink points to. 
        

    archive_read_disk_set_standard_lookup() 
        Used to install a standard set of user and group name lookup functions for reading archives from disk. 
        The mechanisms this function sets up allow for the conversion of user IDs (UIDs) and group IDs (GIDs) 
        into their corresponding names. 



    





        | is used as a bitwise OR operator. It is used to combine multiple options or flasgs into a single argument
        when the options are represented as bit fields or bit masks. 

        Each options is typically defined as a constant e.g. 
        #define ARCHIVE_EXTRACT_TIME       0x01  // Binary: 00000001
        #define ARCHIVE_EXTRACT_PERM       0x02  // Binary: 00000010
        #define ARCHIVE_EXTRACT_ACL        0x04  // Binary: 00000100

        When you do: ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL

        This combines the vlues into a single integer by performing bitwise OR on the binary representations:

        00000001  // ARCHIVE_EXTRACT_TIME
        |  00000010  // ARCHIVE_EXTRACT_PERM
        | 00000100  // ARCHIVE_EXTRACT_ACL
        ------------
        00000111  // Result

        For a function to take args like this you would define it to accept an integer param (typically int or unsigned int
        to hold the flags. Within the function, you can test for specific flags using the bitwise AND operator(&). 

        if (options & ARCHIVE_EXTRACT_TIME) {
            printf("Option: ARCHIVE_EXTRACT_TIME enabled\n");
        }
        if (options & ARCHIVE_EXTRACT_PERM) {
            printf("Option: ARCHIVE_EXTRACT_PERM enabled\n");
        }
        if (options & ARCHIVE_EXTRACT_ACL) {
            printf("Option: ARCHIVE_EXTRACT_ACL enabled\n");
        }

        Can assign options to a variable:     
            unsigned int options = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_OWNER;

    


    Compile with recurse.h
    gcc -D TEST_COPY archive.c -o archive -lssl -lcrypto -larchive


    instead of stat look at using stat64


*/


// // Remove this when linked with the recurse.h (already included in recurse.h)
// typedef enum {
//    UNKNOWN_TYPE = -1, 
//    FILE_TYPE,
//    DIRECTORY_TYPE,
//    SYMLINK_TYPE
// } FileType;


// // This is defined in recurse.h and is in recurse.c (just need to include recurse.h and link recurse.c)
// FileType checkType(mode_t file_type){
//    if(S_ISREG(file_type))
//       return FILE_TYPE;
//    if(S_ISDIR(file_type))
//       return DIRECTORY_TYPE;
//    if(S_ISLNK(file_type))
//       return SYMLINK_TYPE;
// }



int copy_dir(const char* src, const char *dest){
    struct archive *src_archive; 
    struct archive *dest_archive; 
    struct archive_entry *entry; 
    int r; 
    

    // Create a new archive object for reading directory
    src_archive = archive_read_disk_new();
    

    //Configure archive object 
    archive_read_disk_set_standard_lookup(src_archive);    
    archive_read_disk_set_symlink_physical(src_archive);
    
    /*
     * Opens the file or directory from the given path and prepares the struct archive to read it from disk
    */
   r = archive_read_disk_open(src_archive, src);
   if(r != ARCHIVE_OK){
    fprintf(stderr, "Failed to open directory: %s\n", archive_error_string(src_archive));
    archive_read_free(src_archive); 
    return -1; 
   }

    /*
     * Allocate and init a struct archive object suitable for writing objects to disk. 
     * Return: struct archive *
    */  
    dest_archive = archive_write_disk_new();
    if(!dest_archive){
        fprintf(stderr, "Failed to create destination archive.\n");
        archive_read_free(src_archive);
        return -1; 
    }
    
    archive_write_disk_set_options(dest_archive, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL 
                                    | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_NO_OVERWRITE | ARCHIVE_EXTRACT_FFLAGS 
                                    | ARCHIVE_EXTRACT_OWNER);
   
   // Traverse the directory 
   while (archive_read_next_header(src_archive, &entry) == ARCHIVE_OK){
        const char *current_path = archive_entry_pathname(entry); 
        const struct stat *st = archive_entry_stat(entry); 
        char type = '?'; 
       

        // Determine entry type
        if (S_ISREG(st->st_mode)) type = '-';
        else if (S_ISDIR(st->st_mode)) type = 'd';
        else if (S_ISLNK(st->st_mode)) type = 'l';
        else if (S_ISBLK(st->st_mode)) type = 'b';
        else if (S_ISCHR(st->st_mode)) type = 'c';
        else if (S_ISFIFO(st->st_mode)) type = 'p';
        else if (S_ISSOCK(st->st_mode)) type = 's';

        // Print entry informaiton 
        printf("%c %10lld %s\n", type, (long long) st->st_size, current_path);
   
        const char *relative_path = current_path + strlen(src);
        if(*relative_path == '/'){
            relative_path++; // Skip the leading slash 
        }

        // Create the full destination path
        char dest_path[1024];


        
        // snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, src_path); 
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, relative_path); 
        printf("Dest: %s\n", dest_path);

        // Set the new destination path for the entry 
        archive_entry_set_pathname(entry, dest_path);  

        // Write the entry to the destination 
        r = archive_write_header(dest_archive, entry); 
        if (r != ARCHIVE_OK){
            fprintf(stderr, "Failed to write header for %s: %s\n", dest_path, archive_error_string(dest_archive));
            // archive_entry_free(entry); 
            continue; // Skip to next entry
        }
        
        // Copy the file data
        const void *buff; 
        size_t size; 
        la_int64_t offset; 
        while((r = archive_read_data_block(src_archive, &buff, &size, &offset)) == ARCHIVE_OK){
            r = archive_write_data_block(dest_archive, buff, size, offset); 
            if (r != ARCHIVE_OK){
                fprintf(stderr, "Failed to write data for %s: %s\n", dest_path, archive_error_string(dest_archive));
                break; 
            }
        }
        
        if (r != ARCHIVE_EOF && r != ARCHIVE_OK){
            fprintf(stderr, "Error reading data for %s: %s\n", current_path, archive_error_string(src_archive));
        }
        // archive_entry_free(entry); 


        

        // If it's a directory, descent into it
        if (S_ISDIR(st->st_mode)){
            archive_read_disk_descend(src_archive);
        }

   }
   
   

   if (r != ARCHIVE_EOF){
        fprintf(stderr, "Failed to read next header: %s\n", archive_error_string(src_archive));
    }

   // Clean up 
   archive_read_close(src_archive);
   archive_read_free(src_archive);
   archive_write_close(dest_archive); 
   archive_write_free(dest_archive);
   
   
   
   return (r == ARCHIVE_EOF || r == ARCHIVE_OK) ? 0 : -1;
}


int copy_file(const char *src, const char *dest){
    
    struct archive *src_archive; 
    struct archive *dest_archive; 
    struct archive_entry *entry; 
    
    int r; 
    

    // Open the source file for reading  
    src_archive = archive_read_new();
    archive_read_support_format_raw(src_archive); // Returns ARCHIVE_OK on success ARCHIVE_FATAL on failure
 
 
    // archive_read_open_filename(struct archive *, char *filename, size_t block_size)
    if((r = archive_read_open_filename(src_archive, src, 10240))){         
        fprintf(stderr, "Could not open source file: %s\n", archive_error_string(src_archive)); 
        return r; 
    }

    // Open the distination for writing 
    dest_archive = archive_write_disk_new();
    // archive_write_set_options(dest_archive, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    archive_write_disk_set_options(dest_archive, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    
   

    // Copy data from source to destination 
    while((r = archive_read_next_header(src_archive, &entry)) == ARCHIVE_OK){
        const void *buff; 
        size_t size; 
        la_int64_t offset; 

        archive_entry_set_pathname(entry, dest); // set the destination file path 
        if((r = archive_write_header(dest_archive, entry)) != ARCHIVE_OK){
            fprintf(stderr, "Could not write header: %s\n", archive_error_string(dest_archive));
            return r; 
        }
        

        // Write file data 
        while((r = archive_read_data_block(src_archive, &buff, &size, &offset)) == ARCHIVE_OK){
            if(archive_write_data_block(dest_archive, buff, size, offset) != ARCHIVE_OK){
                fprintf(stderr, "Error writing data: %s\n", archive_error_string(dest_archive));
            }
        }
        if (r != ARCHIVE_EOF){
            fprintf(stderr, "Error reading data: %s\n", archive_error_string(src_archive));
            return r; 

        }
        
        
    }
    if (r != ARCHIVE_EOF){
        fprintf(stderr, "Error reading header: %s\n", archive_error_string(src_archive));

    }
    
    archive_read_close(src_archive);
    archive_read_free(src_archive);
    archive_write_close(dest_archive);
    archive_write_free(dest_archive);
 

    return r == ARCHIVE_EOF ? 0 : r;
}







#ifdef TEST_COPY

int main(int argc, char *argv[]){
    if(argc != 3){
        fprintf(stderr, "Usage: %s <source file> <destination file>\n", argv[0]); 
        return 1; 
    }
    

    /* Uncomment for file copy */
    // int result = copy_file(argv[1], argv[2]); 
    // if(result != 0){
    //     fprintf(stderr, "Failed to copy file.\n");
    //     return 1; 
    // }
    
    // printf("File copied successfully!\n");
    
    
    /* File copy */
    if(copy_dir(argv[1], argv[2]) != 0){
        fprintf(stderr, "Failied to copy directory. \n"); 
        return 1; 
    }
    

    printf("Directory copied successfully! \n");
    return 0;
    
}
#endif