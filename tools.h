#ifndef TOOLS_H
#define TOOLS_H

#include <sys/stat.h>

// In recurse.h
typedef enum {
   UNKNOWN_TYPE = -1, 
   FILE_TYPE, // Regular file 
   DIRECTORY_TYPE, // Directory 
   SYMLINK_TYPE, // Symbolic link
//    BLOCK_TYPE,  // Block device (hard drive/SSD)
//    CHAR_TYPE,  // Character device (terminal or serial port)
//    FIFO_TYPE, // FIFO (named pipe)
//    SOCK_TYPE, // Socket 
} FileType;

/*
        Function to check if it is a file, directory, or symbolic link
        You get the argument (mode_t file_type) from stat() (stat().st_mode)

*/ 

// Contains all the possible operations (used in client.c and server.c)
typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 

FileType checkType(mode_t file_type);

char *getFname(char *p);

#endif