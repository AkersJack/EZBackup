#include <stdio.h>
#include <string.h> 
#include <sys/types.h> // mode_t
#include "tools.h"



/*
        A file that is going to contain general helpful functions and tools
        that the project uses 


        To Compile: 
                gcc -g -D TEST_TOOLS tools.c -o tools


*/

char *getFname(char *p){ 
   char *file_name = strrchr(p, '/');
   if(file_name == NULL){
       file_name = p; 
   }else{
       file_name++; 
   }
   return file_name; 
}


FileType checkType(mode_t file_type){
   if(S_ISREG(file_type))
      return FILE_TYPE;
   if(S_ISDIR(file_type))
      return DIRECTORY_TYPE;
   if(S_ISLNK(file_type))
      return SYMLINK_TYPE;
   if(S_ISLNK(file_type))
      return SYMLINK_TYPE;
}




#ifdef TEST_TOOLS
int main(int argc, char *argv[]){

        return 0; 
}

#endif