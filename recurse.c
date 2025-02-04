#include <stdio.h> 
#include <string.h> 
#include "recurse.h"
#include <sys/types.h>
#include <errno.h> 
#include <linux/limits.h>
#include <time.h> 
#include <stdlib.h>
                         


/*
 *  -D defines a macro and controls which parts of the code are compiled 
    use gcc -D TEST_RECURSE recurse.c -o recurse to test this file only 
    

    // This links the openssl 
    gcc -D TEST_RECURSE recurse.c -o recurse -lssl -lcrypto

    // Compile for valgrind
    gcc -g -D  TEST_RECURSE recurse.c -o  recurse -lssl -lcrypto 
    

    The current search algorithm that is currently being used is DFS
        - A potential problem is reaching maximum recursion depth 
            - To solve you could use an explicit stack 
            - Could use BFS as well or a hybrid approach 
    
    
    // Instead of stat look at using stat64 to handle files larger than 2GB 
*/

// Returns 1 if files are identical, 0 if differnet, -1 on error



char *getFname(char *p){ 
    char *file_name = strrchr(p, '/');
    if(file_name == NULL){
        file_name = p; 
    }else{
        file_name++; 
    }
    return file_name; 
}


void init_stack(DirStack *s){
    s->top = NULL;
    s->size = 0;
}

// Check if the stack is empty 
bool is_empty(DirStack *s){
    return s->top == NULL; 
}

// Pushelement onto stack 
bool push(DirStack *s, const char *path){
    Node *newNode = malloc(sizeof(Node)); 
    if(!newNode){
        perror("Memory allocation failed!\n");
        return false;
    }
    
    // Allocate memory for string and copy it
    newNode->path = (char*)malloc(strlen(path) + 1); 
    if(!newNode->path){
        perror("Memory allocation failed! \n");
        free(newNode); 
        return false;
    }
    strcpy(newNode->path, path); 
    
    newNode->next = s->top; 
    s->top = newNode; 
    s->size++; 
    
    return true; 
}


// Pop element from stack
char* pop(DirStack *s){
    if(is_empty(s)){
        printf("Stack underflow!\n");
        return NULL;
    }
    Node *temp = s->top; 
    char *path = temp->path; 
    s->top = temp->next; 
    free(temp); 
    s->size--; 
    return path; // Caller is responsible for freeing this 
}


// Peek at top element 
const char* peek(DirStack *s){
    if(is_empty(s)){
        printf("Stack is empty \n"); 
        return false; 
    }
    return s->top->path;
}


// Free stack memory 
void free_stack(DirStack *s){
    Node *current = s->top; 
    while (current){
        // printf("Stack Size: %d\n", s->size);
        Node *next = current->next; 
        free(current->path);
        current->path = NULL;
        free(current);
        current = next;
        s->size--; 
    }
    s->top = NULL; 
    s->size = 0; 
}



int file_cmp(const char *fpath_1, const char *fpath_2){
    FILE  *file1 = fopen(fpath_1, "rb");
    FILE  *file2 = fopen(fpath_2, "rb");
    
    if(!file1 || !file2){
        if(file1) fclose(file1); 
        if(file2) fclose(file2); 
        return -1; 
    }

    // Stores the hashes 
    unsigned char hash1[MD5_DIGEST_LENGTH]; 
    unsigned char hash2[MD5_DIGEST_LENGTH]; 

    MD5_CTX md5; // Stores intermediate state of hash calculation 
    unsigned char buffer[4096]; // Used to read data from the files in chunks 
    size_t bytes; // Used to store the number of bytes read from the file in each iteration
    
    // Calculate hash of first file 
    MD5_Init(&md5); // Init the MD5 context 

    // Read data from file1 into the buffer in chunks of sizeof(buffer) bytes
    // fread() returns the number of bytes actually read 
    // Continues as long as data is successfully read 
    while ((bytes = fread(buffer, 1, sizeof(buffer), file1)) != 0){
        MD5_Update(&md5, buffer, bytes); // Update md5 context with the data read from the file
    }
    MD5_Final(hash1, &md5); // Finalize the MD5 calculation and store the resulting hash in hash1 array
    
                            


    // Calculate hash of second file
    MD5_Init(&md5);
    while ((bytes = fread(buffer, 1, sizeof(buffer), file2)) != 0){
        MD5_Update(&md5, buffer, bytes);
    }
    MD5_Final(hash2, &md5); 

    fclose(file1); 
    fclose(file2);
    
return memcmp(hash1, hash2, MD5_DIGEST_LENGTH) == 0;  
}

int file_cmp_single(unsigned char *fhash, const char *fpath){
    FILE  *file = fopen(fpath, "rb");
    
    if(!file)
        return -1; 

    // Stores the hashes 
    unsigned char hash[MD5_DIGEST_LENGTH]; 

    MD5_CTX md5; // Stores intermediate state of hash calculation 
    unsigned char buffer[4096]; // Used to read data from the files in chunks 
    size_t bytes; // Used to store the number of bytes read from the file in each iteration
    
    // Calculate hash of first file 
    MD5_Init(&md5); // Init the MD5 context 

    // Read data from file1 into the buffer in chunks of sizeof(buffer) bytes
    // fread() returns the number of bytes actually read 
    // Continues as long as data is successfully read 
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0){
        MD5_Update(&md5, buffer, bytes); // Update md5 context with the data read from the file
    }
    MD5_Final(hash, &md5); // Finalize the MD5 calculation and store the resulting hash in hash1 array
    
                            

fclose(file);

    return memcmp(fhash, hash, MD5_DIGEST_LENGTH) == 0;  
}


unsigned char* gen_fhash(const char *fpath){

    
    FILE  *file = fopen(fpath, "rb");
    
    if(!file)
        return NULL; 

    // Stores the hashes 
    unsigned char *hash = malloc(MD5_DIGEST_LENGTH); 

    MD5_CTX md5; // Stores intermediate state of hash calculation 
    unsigned char buffer[4096]; // Used to read data from the files in chunks 
    size_t bytes; // Used to store the number of bytes read from the file in each iteration
    
    // Calculate hash of first file 
    MD5_Init(&md5); // Init the MD5 context 

    // Read data from file1 into the buffer in chunks of sizeof(buffer) bytes
    // fread() returns the number of bytes actually read 
    // Continues as long as data is successfully read 
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0){
        MD5_Update(&md5, buffer, bytes); // Update md5 context with the data read from the file
    }

    MD5_Final(hash, &md5);
    return hash; 
}

FileType checkType(mode_t file_type){
   if(S_ISREG(file_type))
      return FILE_TYPE;
   if(S_ISDIR(file_type))
      return DIRECTORY_TYPE;
   if(S_ISLNK(file_type))
      return SYMLINK_TYPE;
}

 
// Compare certain stats between the two files (if stats match then compare hash)
// Returns 1 if identical, 0 if different, -1 on error 
int file_cmp_stat(struct stat *f1, struct stat *f2){
    


    return 0; 
    
}

// struct stat search(char *file_name, char* path){
// file can be a string which has the file path or a md5 hash ftype is 0 for string path 1 for md5
// File can be a struct which has the file hash, stat, and file path, or just the file path
// struct stat search(void *file, char* path, int ftype){
// struct stat search(FileInfo *file, char* path){
struct stat search(FileInfo *file, DirStack *s){
    DIR *dirp;
    
    // printf("Stack Size: %d\n", s->size);
    char *path = pop(s); 

    dirp = opendir(path);

    // printf("Directory Start %s\n", path); 


    struct dirent *dp; 

    struct stat file_stat; 
    struct stat empty_stat; 

    
    // Make the empty_stat empty 
    memset(&empty_stat, 0, sizeof(struct stat));

    if(!dirp){
        perror("opendir");
        return empty_stat; 
    }
    

    while(dirp){
        errno = 0;

        if ((dp = readdir(dirp)) != NULL){

            if(strcmp(dp->d_name, ".") && strcmp(dp->d_name, "..") != 0){

                char full_path[PATH_MAX];
                snprintf(full_path, sizeof(full_path), "%s/%s", path, dp->d_name);

                if(stat(full_path, &file_stat) < 0){
                    printf("Full path: %s\n",full_path);
                    perror("stat failed");
                    continue; // Move to the next iteration of the while loop if stat fails
                }

                struct tm *tm_info; 
                FileType ft; 

                switch(checkType(file_stat.st_mode)){

                    case FILE_TYPE: 
                        // printf("File: %s\n", full_path); 
                        ft = FILE_TYPE; 
                        
                        // st_ino is a unique identifier for files on an OS (could use that potentially)
                        // CMP the file size, user id, and Group ID of the file. If all are the same check the hash  
                        if(!strcmp(file->name, dp->d_name) && file->fstat.st_size == file_stat.st_size && file->fstat.st_uid == file_stat.st_uid && file->fstat.st_gid == file_stat.st_gid){

                        // Perform multiple checks on file info before hash 
                            if(file_cmp_single(((FileInfo*)file)->hash, full_path)){
                                printf("Found File: %s\n", full_path);                            
                                closedir(dirp);                       
                                return file_stat;
                                
                            }
                        }
                            
                        break;

                    case DIRECTORY_TYPE: 
                        // printf("File: %s\n", full_path); 
                        ft = DIRECTORY_TYPE;

                        // Push the new directory onto the stack 
                        push(s, full_path);
                        char *stack_top; 
                        // printf("Added: %s\n", peek(s));
                        
                        
                        

                        // struct stat result = search(file, full_path); 
                        // If found in recursive call, return immediately
                        // if (result.st_size > 0){
                        //     closedir(dirp); 
                        //     return result;
                        // }
                        break;
                        

                    case SYMLINK_TYPE: 
                        // printf("File: %s\n", full_path); 
                        ft = SYMLINK_TYPE;
                        break;

                    default:  
                        // printf("Unknown Type: %s\n", full_path); 
                        ft = UNKNOWN_TYPE;
                        break; 
                        
                }     

            }
            // After we add in all the directories recurse using the stack (pop items) or we could just use a while loop
            



        }else{
            break;
        }


    }

    // struct stat result = search(file, s); 
    //             //If found in recursive call, return immediately
    // if (result.st_size > 0){
    //     closedir(dirp); 
    //     return result;
    // }

    free(path);
    closedir(dirp);
    return empty_stat; // Return star (stat with nothing in it) if the file isn't found 
}


#ifdef TEST_RECURSE

int main(int argc, char *argv[]){
    printf("Search for: %s\n", argv[1]);
    printf("Start Location: %s\n", argv[2]);
    
    // Init the stack 
     DirStack *stack = malloc(sizeof(DirStack));

     if(!stack){ 
         perror("Error: malloc failed"); 
         return -1;
     }

     init_stack(stack); 
     
    
    FileInfo *fileInfo = malloc(sizeof(FileInfo)); 


    if(fileInfo == NULL){
        perror("Error: malloc failed");
        return -1;
    }





    unsigned char *fhash = gen_fhash(argv[1]);
    struct stat f_info; 
    
    int stat_return = stat(argv[1], &f_info); 
 
    
    
    
    if(stat_return < 0){
        printf("Full Path: %s\n", argv[1]); 
        perror("Error: stat failed"); 
        free(fileInfo); 
        free(fhash);
        return 1; 
    }
    

    fileInfo->path = argv[1];
    fileInfo->fstat = f_info; 
    fileInfo->hash = fhash; 
    fileInfo->name = getFname(argv[1]); 
    
    

    

    
    push(stack, argv[2]);


    

    
    
    



    

    // // Check if gen_fhash returns NULL here
    // for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
    //     printf("%02x", fileInfo->hash[i]);
    // }
    // printf("\n");
    
    // Run if you have a hash for the file you are searching for 
    // search(fhash, argv[2], 1);
    // search(fileInfo, argv[2]);
    
    while(stack->size){
        struct stat result = search(fileInfo, stack);

        if (result.st_size > 0){
            break;
        }

    }
    
    free(fhash);
    free(fileInfo);
    free_stack(stack);
    free(stack);
    stack = NULL; 
    
    // Run if you don't generate a hash for the file you are searching for
    // search(argv[1], argv[2], 0);

    return 0; 
}

#endif
