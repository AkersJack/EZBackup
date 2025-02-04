#ifndef RECURSE_H
#define RECURSE_H


#include <dirent.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <pthread.h> 



// Returns 1 if files are identical, 0 if differnet, -1 on error
int file_cmp(const char *fpath_1, const char *fpath_2);  


// Returns 1 if files are identical, 0 if differnet, -1 on error
int file_cmp_single(unsigned char *fhash, const char *fpath);


unsigned char* gen_fhash(const char *fpath);

typedef enum {
   UNKNOWN_TYPE = -1, 
   FILE_TYPE,
   DIRECTORY_TYPE,
   SYMLINK_TYPE
} FileType;


typedef struct FileInfo{
   char *path;
   char *name; 
   unsigned char *hash;
   struct stat fstat; 
} FileInfo;


// Get the file name from a path 
char* getFname(char *p);

// Compare certain stats between the two files (if stats match compare hash)
int file_cmp_stat(struct stat *f1, struct stat *f2); 


// Function to check if it is a file, directory, or symbolic link
FileType checkType(mode_t file_type);


// Linked List-based stack (for directories)
typedef struct Node{
    char *path; 
    struct Node *next; 

} Node; 


typedef struct{
    Node* top; 
    int size;

} DirStack;


void init_stack(DirStack *s); 

bool is_empty(DirStack *s); 

bool push(DirStack *s, const char *path);

char* pop(DirStack *s);

const char* peek(DirStack *s); 

void free_stack(DirStack *s);

// struct stat search(FileInfo *file, char *path);
struct stat search(FileInfo *file, DirStack *s);










#endif