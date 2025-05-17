#include "config.h"
#include <unistd.h> // access()
#include <stdlib.h>
#include <sys/stat.h>


int init_custom_config(const char* path){
        FILE *file; 
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

        /* remote address to connect to when connecting to a server */
        if(cJSON_AddStringToObject(root, "remote_addr", "localhost") == NULL){
                perror("Failed to add string to object (Backup_Address)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        /* Port to connect to (when connecting to server)*/
        if(cJSON_AddStringToObject(root, "remote_port", "8080") == NULL){
                perror("Failed to add string to object (remote_port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        /* Port to run the server on */
        if(cJSON_AddStringToObject(root, "port", "8080") == NULL){
                perror("Failed to add string to object (port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        /* Actually write and save the files */
        if(cJSON_AddBoolToObject(root, "write_files", 0) == NULL){
                perror("Failed to add string to object (port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        if(cJSON_AddStringToObject(root, "backup_location", "./backup/") == NULL){
                perror("Failed to add string to object (port)"); 
                cJSON_Delete(root); 
                return 1;  
        }
        
        
        char *json_string = cJSON_Print(root); 
        // printf("%s\n", json_string);

        FILE *outfile = fopen("config.json", "w"); 
        if(outfile == NULL){
                perror("Faield to open config.json file.\n"); 
                free(json_string); 
                cJSON_Delete(root); 
                return 1; 
                
        }

        // fprintf(outfile, "%s", json_string); 
        fputs(json_string, outfile);
        fclose(outfile); 
        free(json_string);
        cJSON_Delete(root);

}



int readCustomConfig(const char *path, cJSON **obj){
        FILE *file = fopen(path, "r"); 
        struct stat st; 
        long fsize; 

        if(!file){
                fprintf(stderr, "Error opening file %s\n", path);
                return 1; 
        }


        if(stat(path, &st) != 0){
                perror("Error getting file size");
                fclose(file); 
                return 1;
        }
        
        fsize = st.st_size; 

        char *buffer = malloc(fsize + 1); 
        if(!buffer){
                perror("Failed to allocate buffer when reading config"); 
                fclose(file); 
                return 1; 
        }

        size_t bytes_read = fread(buffer, 1, fsize, file); 
        if(bytes_read != (size_t)fsize){
                perror("Error reading config file"); 
                free(buffer); 
                fclose(file); 
                return 1; 
        }
        buffer[fsize] = '\0'; 
        fclose(file); 
        
        cJSON *root = cJSON_Parse(buffer); 
        if(root == NULL){
                const char *error_ptr = cJSON_GetErrorPtr(); 
                if(error_ptr != NULL){
                        fprintf(stderr, "Error before: %s\n", error_ptr); 
                }else{
                        printf("Error: Unable to parse JSON file (no error ptr).\n");
                }
                free(buffer); 
                return 1; 
        }
        
        free(buffer);
        cJSON *tmp = *obj;
        *obj = root; 
        cJSON_Delete(tmp);
        


        return 0; 
}


int readConfig(cJSON **obj){
        const char *filename = "./config.json";
        struct stat st; 
        long fsize; 

        FILE *file = fopen(filename, "r");
        if(!file){
                perror("Error opening config.json"); 
                return 1; 
        }
        
        if(stat(filename, &st) != 0){
                perror("Error getting file size");
                fclose(file); 
                return 1;
        }

        fsize = st.st_size; 
        char *buffer = malloc(fsize + 1); 
        if(!buffer){
                perror("Failed to allocate buffer when reading config"); 
                fclose(file); 
                return 1; 
        }

        size_t bytes_read = fread(buffer, 1, fsize, file); 
        if(bytes_read != (size_t)fsize){
                perror("Error reading config file"); 
                free(buffer); 
                fclose(file); 
                return 1; 
        }
        buffer[fsize] = '\0'; 
        fclose(file); 

        cJSON *root = cJSON_Parse(buffer); 
        if(root == NULL){
                const char *error_ptr = cJSON_GetErrorPtr(); 
                if(error_ptr != NULL){
                        fprintf(stderr, "Error before: %s\n", error_ptr); 
                }else{
                        printf("Error: Unable to parse JSON file (no error ptr).\n");
                }
                free(buffer); 
                return 1; 
        }
        
        free(buffer);

        cJSON *tmp = *obj;
        *obj = root; 
        cJSON_Delete(tmp);
        
        return 0; 
        
}


int checkFile(){
        
        printf("NEED TO IMPLEMENT! (checkFile() config.c)\n");
        return 0; 
}