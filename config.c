#include "config.h"
#include <unistd.h> // access()

int initConfig(){
        FILE *file; 
        const char *path = "./config.json";
        if(access(path, F_OK) != 0){
                if(errno == ENOENT){
                        printf("File %s does not exist.\n", path); 
                        file = fopen(path, "w+");
                        if(file == NULL){
                                // fprintf(stderr, "Error creating config file: %s\n", strerror(errno));  
                                perror("Error creating config file");
                                return 1; 
                        }

                }else{
                        // fprintf(stderr, "Error: %s\n", strerror(errno)); 
                        perror("Error unable to access config file");
                        return 1; 
                }
        }

        return 0; 
}

int buildConfig(){
        printf("Building config\n");
        cJSON *root = cJSON_CreateObject(); 
        if(cJSON_AddStringToObject(root, "remote_addr", "localhost") == NULL){
                perror("Failed to add string to object (Backup_Address)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        if(cJSON_AddStringToObject(root, "remote_port", "8080") == NULL){
                perror("Failed to add string to object (remote_port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        if(cJSON_AddStringToObject(root, "port", "8080") == NULL){
                perror("Failed to add string to object (port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        
        char *json_string = cJSON_Print(root); 
        printf("%s\n", json_string);
        cJSON_Delete(root);

}

int checkFile(){
        
        return 0; 
}