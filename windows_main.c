#include <stdio.h> 
#include <windows.h> 
#include <string.h> 



/* 
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/

BackupRead (can be used to backup a file or directory)
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread


BackupWrite (Used to write a file/directory that was backed up using BackupRead)
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite


FindClose (close a file search handle opened by the FindFirstFile)
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findclose
      
FindFirstFileA (Searches a directory for a file or subdirectory with a name that matches a specific name (or partial name if wildcards are used). (ANSI)
)
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilea

FindFirstFileExA (Searches a directory for a file or subdirectory with a name and attributes that match those specified. (FindFirstFileExA)
)
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilea


GetFileAttributes
https://learn.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-getfileattributesa
*/




















int main(int argc, char *argv[]){
    WIN32_FIND_DATA findFileData; 
    HANDLE hFind;
    
    // Specify the directory and file pattern (e.g., "*.*" for all files)
    char directory[100]; 
    strncpy(directory, argv[1], sizeof(directory) - 1); 
    directory[sizeof(directory) - 1] = '\0'; 
    strcat(directory, "*.*");
    
    // Start finding the first file in the directory 
    hFind = FindFirstFile(directory, &findFileData); 
    if (hFind == INVALID_HANDLE_VALUE){
        printf("Error: Unable to open directory. Check the path. \n"); 
        return 1; 

    }else{
        printf("Files in directory: \n"); 
        do {
            // Check if the current item is a directory  
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                printf("    [DIR] %s\n", findFileData.cFileName);
            }else{
                // Calculate file size (high and low parts combined)
                LARGE_INTEGER filesize; 
                filesize.HighPart = findFileData.nFileSizeHigh; 
                filesize.LowPart = findFileData.nFileSizeLow; 
                

                printf("    [FILE] %s - Size: %lld bytes\n", findFileData.cFileName, filesize.QuadPart);
            }
        }while(FindNextFile(hFind, &findFileData) != 0); // Continue to the next file
        
        // Close the handle when done 
        FindClose(hFind); 
    }
    
    
    



}


