#ifndef LIBARCH_H
#define LIBARCH_H

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h> 
 
/*
    Purpose of libarch.h
        - Create archives of files/directories that can be sent 
        - Compress archives using various methods of compression 
        - Decrompress and open various different archives
        - List items in an archive 
        - Browse archives (be able to traverse archives with ease)

*/

int archive_stream_files(const char **files, int sock, char* options, int num_files);




#endif 