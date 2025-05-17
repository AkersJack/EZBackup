#include "test.h"
#include <sys/wait.h>

// valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./example arg1 arg2
/* Generally speaking this file will test everything */

/*
 * Returns 0 on success anything else is an error 
*/
int testServer(cJSON *config){
        int sfd = 0; 

        cJSON *cjson_port = cJSON_GetObjectItemCaseSensitive(config, "port");
        char *port = cjson_port->valuestring;
        printf("Server Port: %s\n", port);

        initServer(port, &sfd);
        startServer(sfd, config);
        close(sfd); 

        printf("Server Testing Complete\n"); 
        return 0; 

}


int init_fileContainer(cJSON *files, struct fileContainer *fc){
    if(!cJSON_IsArray(files)){
        perror("Item is not a JSON array"); 
        return 1; 
    }
    
    // Set the max to 10 files for now 
    int max_files = 10; 
    char **fc_files = malloc(sizeof(char *) * max_files);
    struct stat st; 
    

    cJSON *file_item;
    int i = 0;
    cJSON_ArrayForEach(file_item, files) {
            if (cJSON_IsString(file_item)) {
                    if (stat(file_item->valuestring, &st) != 0) {
                            fprintf(stderr, "Failed to stat input file %s\n", file_item->valuestring);
                            continue;
                    } else {
                            printf("File %d: %s\n", i, file_item->valuestring);

                            size_t string_size = strnlen(file_item->valuestring, PATH_MAX);
                            string_size++; // Include null terminator
                            printf("String size: %lu\n", string_size);
                            char *new_string = malloc(string_size); 
                            strncpy(new_string, (file_item->valuestring), string_size);
                            fc_files[i] = new_string;
                            i++;
                            if(i >= (max_files - 1)){
                                max_files += 10; 
                                fc_files = realloc(fc_files, sizeof(char *) * max_files);
                                if(!fc_files){
                                        perror("realloc fc_files failed"); 
                                        exit(EXIT_FAILURE);
                                }
                            }
                    }
            }
    }
    
    fc->files = fc_files; 
    fc->num_files = i;

    return 0;
}

/*
 * Used for testing the file transfer
*/
int test_FT(const int sock, cJSON *config){
    struct fileContainer fc; 
    
    if(!cJSON_IsObject(config)){
        printf("Item is not a JSON object.\n");
    }else{
        ((void) 0);
    }
    
    /* Might need to change this depending on if the test.config file changes */
    cJSON *current_item = config->child; 
    while(current_item != NULL){
        printf("Running Test: %s\n", current_item->string); 
        cJSON *file_array = cJSON_GetObjectItemCaseSensitive(current_item, "files"); 
        // cJSON *file_item; 
        // int i = 0; 
        // cJSON_ArrayForEach(file_item, file_array){
        //         if(cJSON_IsString(file_item)){
        //                 printf("File %d: %s\n", i, file_item->valuestring);
        //         }
        //         i++; 
        // }
        
        struct fileContainer fc; 
        
        init_fileContainer(file_array, &fc);
        freeFileContainer(&fc);
        
        
        cJSON *fname = cJSON_GetObjectItemCaseSensitive(current_item, "fname"); 
        if(cJSON_IsString(fname)){
                printf("Fname: %s\n", fname->valuestring);
        }
        printf("\n"); 

        current_item = current_item->next;
        
    }


    

    return 0;
}
int testFileTransfer(cJSON *config){
        char *json_string = cJSON_Print(config); 
        if(json_string == NULL){
                perror("Failed to print JSON Object"); 
                return 1; 
        }
        
        // printf("Config File:\n %s", json_string); 

        int sock = 0; 

        test_FT(sock, config);
        

        free(json_string); 


        


        return 0; 
}



int main(int argc, char *argv[]){

        /* This is the config file for testing */
        cJSON *test_config = cJSON_CreateObject(); 
        if(test_config == NULL){
                perror("Failed to create cjson test_config object"); 
                return 1; 
        }
        char *path = "test.json";
        readCustomConfig(path, &test_config);
 
        /* This is the config file for the actual server and client */
        cJSON *config = cJSON_CreateObject(); 
        if(config == NULL){
                perror("Failed to create cjson config object"); 
                cJSON_Delete(test_config); 
                return 1; 

        }
        readConfig(&config);

        cJSON *cjson_port = cJSON_GetObjectItemCaseSensitive(config, "port");
        char *port = cjson_port->valuestring;
        
        cJSON *cjson_address = cJSON_GetObjectItemCaseSensitive(config, "remote_addr"); 
        char *address = cjson_address->valuestring;

        
        printf("Port: %s\n", port);
        printf("Address: %s\n", address); 

        testServer(config);
        
        testFileTransfer(test_config); 
 


        cJSON_Delete(config); 
        cJSON_Delete(test_config); 

        

        printf("Testing Complete\n"); 
        

        return 0; 

}