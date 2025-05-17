/* 
        Essentially a refined version of server_NT.c
*/

#include "server.h"
#include <openssl/md5.h>



int initServer(char *port, int *sock){
        
        
        int gai, sfd, new_fd; 
        char buf[BUF_SIZE]; 
        ssize_t nread; 
        struct addrinfo hints; 
        struct addrinfo *result, *rp;
        struct sockaddr_in server_addr; 
        socklen_t server_addrlen = sizeof(server_addr);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;      // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM;  // Socket Stream
        // hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;  // TCP protocol
        hints.ai_flags = 0;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        /*
            getaddrinfo() returns a list of address structures.
            Try each address until we successfully bind(2).
            If socket(2) (or bind(2)) fails, we close the socket
            and try the next address.
        */
        gai = getaddrinfo(NULL, port, &hints, &result); 

        /* Write check here to ensure that gai succeeds*/
        if(gai != 0){
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai)); 
                exit(EXIT_FAILURE); 
        }

        for (rp = result; rp != NULL; rp = rp->ai_next){
                sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); 
                if (sfd == -1){
                        continue;
                }
                if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0){
                        break; /* Success */
                }
                close(sfd); 
        } 

        /* Check if binding succeeded */
        if(rp == NULL){
                fprintf(stderr, "Could not bind to any address using port (%s)\n", port);
                exit(EXIT_FAILURE);
        }

        /* Output server address and port */
        getsockname(sfd, (struct sockaddr *)&server_addr, &server_addrlen);
        if (server_addr.sin_family == AF_INET) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(server_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
                printf("Socket bound at address: %s:%d\n", ip_str, ntohs(server_addr.sin_port));

        } else {
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&server_addr)->sin6_addr), ip_str, INET6_ADDRSTRLEN);
                printf("Socket bound at address: %s:%d\n", ip_str, ntohs(((struct sockaddr_in6 *)&server_addr)->sin6_port));
        }

        freeaddrinfo(result); /* No longer needed */
        
        /* No address succeeded */
        if(rp == NULL){
                fprintf(stderr, "Could not bind.\n");  
                exit(EXIT_FAILURE); 
        }

        /* Add max number of connections to config */
        if(listen(sfd, 10) == -1){
                perror("listen");
                close(sfd); 
                exit(1); 
        }



        *sock = sfd; 

        return 0;
}

size_t writeData(char *buff, size_t length, int fd){
        size_t bytes_written = 0; 
        while(bytes_written != length){
                ssize_t written = write(fd, buff + bytes_written, length - bytes_written);    
                if (written == -1){
                        perror("Write error"); 
                        return 0; 
                }
                bytes_written += written; 
        }
        return bytes_written; 

}

unsigned char* hashString(const char *str){
        
        unsigned char *hash = malloc(MD5_DIGEST_LENGTH);
        printf("%s\n", str); 
        MD5_CTX md5; 
        MD5_Init(&md5); 
        MD5_Update(&md5, str, strlen(str)); 
        MD5_Final(hash, &md5); 
        return hash; 
}

void print_md5_hex(unsigned char *digest){
        for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
                printf("%02x", digest[i]);
        }
        printf("\n"); 
}

// Need to open the file and close the file in the function that calls this function
int readClientData(char *buffer, int socket, cJSON *metadata, int fd){
        int offset = 0;
        uint32_t json_size; 
        uint32_t jsize; 
        size_t buffsize = 10240; 
        ssize_t numbytes = 0; 
        size_t total_written = 0;
        
        // retrieve the json size from the buffer 
        // memcpy(&jsize, buffer, sizeof(uint32_t)); 
        

        // json_size = ntohl(jsize); 
        // printf("Json Size: %u\n",  json_size); 
        
        // char *json_string = malloc(json_size); 
        

        // retrieve the metadata from the buffer (the actual json file data)
        // numbytes = recv(socket, json_string, json_size, 0);
        // /* Client disconnects (not graceful)*/
        // if (numbytes == -1) {
        //         perror("recv");
        //         return -1; // error -1 is client disconnect

        // } else if (numbytes == 0) { /* Graceful disconnect */
        //         printf("Lost connection to the server (Socked FD: %d).\n", socket);
        //         return -1; 
        // } 


        // readMetadata(socket, &root);

        // memcpy(&json_size, buffer + offset, sizeof(uint32_t)); 

        // offset += sizeof(u_int32_t); 
        // Segmentation fault here
        // printf("json_size: %d\n", json_size); 
        // char *json_string = malloc(json_size); 
        // json_string = memcpy(json_string, buffer + offset, json_size);
        // ssize_t hash_check; 
        
        // printf("Header Bytes Received: %ld\n", sizeof(uint32_t) + json_size); 

        // The sent json item should be sent as a json string (maybe a better way to do this)
        // printf("JSON string: %s\n", json_string); 
        

        

        // unsigned char *json_md5_hash = hashString(json_string); 

        // // Send md5_hash to check to ensure json was read properly 
        // if ((hash_check = send(socket, json_md5_hash, MD5_DIGEST_LENGTH, 0)) == -1) {
        //         perror("send");
        //         close(socket);  // Might not want to close (possibly try again)
        //         free(json_md5_hash);
        //         return -1;
        // }
        


        // print_md5_hex(json_md5_hash); 

        // free(json_md5_hash); 

        
        /* 
         * Read Json Data here
         * Convert that json string back into a json object
        */
        // Error check this
        // cJSON *root = cJSON_Parse(json_string);
        // if(root == NULL){
        //         const char *error_ptr = cJSON_GetErrorPtr(); 
        //         if (error_ptr != NULL){
        //                 fprintf(stderr, "Error before: %s\n", error_ptr); 
        //         }
        //         return 1; // 1 is error
        // }
        
        

        cJSON *_data_size = cJSON_GetObjectItemCaseSensitive(metadata, "size"); 
        double data_size = 0; 
        if(_data_size != NULL && cJSON_IsNumber(_data_size)){
                data_size = _data_size->valuedouble; 
                printf("Data size: %lf\n", data_size); 
        }else{
                fprintf(stderr, "Could not find 'size' or it's not a number.\n"); 
                return 1; 
        }
        
        
        
        
        double received = 0;  
        char *newBuff = malloc(buffsize); 

        // int fd; 
        size_t written; 
        

        // char *save_location; 
        
        // cJSON *save_loc_obj = cJSON_GetObjectItemCaseSensitive(config, "backup_location");
        // if(cJSON_IsString(save_loc_obj) && (save_loc_obj != NULL)){
        //         save_location = save_loc_obj->valuestring; 
        // }else{
        //         perror("No save location set");
        //         return 1;
        // }
        

        // fd = open(save_location, O_WRONLY| O_CREAT |O_TRUNC, 0644);
        // if (fd < 0){
        //         perror("Failed to access save location");
        //         return 1; 
        // }

        
        // Now receive the actual data
        while(received < data_size){
                bzero(newBuff, buffsize);
                
                size_t remaining = data_size - received; 
                size_t to_receive = (remaining < buffsize) ? remaining : buffsize; 
                
                printf("Getting data\n");
                numbytes = recv(socket, newBuff, to_receive, 0);
                /* Client disconnects (not graceful)*/
                if (numbytes == -1) {
                        perror("recv");
                        return -1; // error -1 is client disconnect

                } else if (numbytes == 0) { /* Graceful disconnect */
                        printf("Client disconnected gracefully (Socked FD: %d).\n", socket);
                        return -1; 
                } 
                received += numbytes;
                printf("Received %lf/%lf bytes\n", received, data_size);
                // written = writeData(newBuff, (size_t)numbytes, fd);
                // total_written += written; 
                // printf("total written: %zu\n", total_written);
                // if(!written){
                //         perror("Failed to write data to file");
                //         return -1;
                // }
                // printf("Wrote %zu bytes\n", written);

        }
        
        
        // close(fd); 
        free(newBuff);
        // free(json_string); 



        
        return 0; 
}




int handle_client(int socket, cJSON *config){
        printf("Server: Got connection on socket %d\n", socket); 
        ssize_t bytes_received; 
        int t = 0;

                        
        int numbytes; 

        /* Check buffer for error */
        char *buffer = malloc(sizeof(uint32_t)); 
        // uint32_t *buffer = malloc(sizeof(uint32_t));
        // char buffer[BUF_SIZE]; 

        int fd; 

        char *save_location; 
        
        cJSON *save_loc_obj = cJSON_GetObjectItemCaseSensitive(config, "backup_location");
        if(cJSON_IsString(save_loc_obj) && (save_loc_obj != NULL)){
                save_location = save_loc_obj->valuestring; 
        }else{
                perror("No save location set");
                return 1;
        }
        

        fd = open(save_location, O_WRONLY| O_CREAT |O_TRUNC, 0644);
        if (fd < 0){
                perror("Failed to access save location");
                return 1; 
        }
        
        cJSON *metaData = NULL; 
        int rm = 0;

        while(1){
                printf("Waiting for client...\n");
                // Getting the size of the JSON data (how big is the metadata header)
                // numbytes = recv(socket, buffer, sizeof(uint32_t), 0);
                
                if((rm = readMetadata(socket, &metaData)) != 0){ 
                        if(rm == -1){
                                perror("recv"); 
                                close(socket); 
                                break; 
                        }else{
                                // printf("Client disconnected gracefully (Socked FD: %d).\n", socket);
                                break;
                        }
                }
                // printf("Metadata size is: %d\n", numbytes);
                // printf("New Message\n");
                /* Maybe use recvmsg() with the struct msghdr  */

                /* An application can use select(2), poll(2), or epoll(7) to determine when more data arrives on a socket. */

                /* Client disconnects (not graceful)*/
                // if (numbytes == -1) {
                //         perror("recv");
                //         close(socket);
                //         break;

                // } else if (numbytes == 0) { /* Graceful disconnect */
                //         printf("Client disconnected gracefully (Socked FD: %d).\n", socket);
                //         break;
                // } 
                
                // readClientData(buffer, socket, config, fd); 
                readClientData(buffer, socket, metaData, fd); 
                
        }
        close(fd); 
        free(buffer); 

        return 0;
}


/*
 * Old send structure:
 *   
 * - Get metadata/json file size
 * - read the metadata/json file
 * - process the json file
 * - Based on what the metadata file says read that much data 
 * - (Repeat all steps)
 * 
 * New Optimized send structure:
 *  - Get metadata/json file size
 *  - read the metadata/json file
 *  - process the json file
 *  - based on what the metadata file says read that much data
 *      - read 4 bytes this is the size of the next chunk of data 
 *      - read that chunk of data 
 *      - repeat until the read 4 bytes reads in all 0's meaning end of stream. 
 *
 *  - Once complete send closing metadata to confirm transfer success 
 *      - Number of chunks/frames that were sent
 *      - size of each frame 
 *      - total data sent 
 *
 *  
 * 
 *  
 * 
 * 
*/

/*
 * Reads metadata info from the data stream (works on start and end of a stream)
 * 
 * Data will be saved to the cJSON object argument 
*/
int readMetadata(int sock, cJSON **config){
        
        char buf[BUF_SIZE] = {0}; 
        
        ssize_t numbytes; 
        int offset = 0; 
        
        uint32_t jsize, json_size;

        numbytes = recv(sock, buf, sizeof(uint32_t), 0);
        if (numbytes == -1) {
                perror("Error receiving metadata size");
                return -1; 

        } else if (numbytes == 0) { /* Graceful disconnect */
                printf("Client disconnected gracefully (Socked FD: %d).\n", sock);
                return 1;
        }

        memcpy(&jsize, buf, sizeof(uint32_t)); 
        

        json_size = ntohl(jsize); 
        printf("Json Size: %u\n",  json_size); 
        
        char *json_string = malloc(json_size); 
        numbytes = recv(sock, json_string, json_size, 0);

        
        if (numbytes == -1) {
                perror("Error receiving metadata (JSON string)");
                return 1; 

        } else if (numbytes == 0) { /* Graceful disconnect */
                printf("Client disconnected gracefully (Socked FD: %d).\n", sock);
                return -1;
        }
        
        printf("JSON string: %s\n", json_string); 
        
        // 0x01 = 1
        // 0x02 = 0x01
        // 0x04 = 0x02
        

        /* 
         * Read Json Data here
         * Convert that json string back into a json object
        */
        // Error check this
        cJSON *root = cJSON_Parse(json_string);
        if(root == NULL){
                const char *error_ptr = cJSON_GetErrorPtr(); 
                if (error_ptr != NULL){
                        fprintf(stderr, "Error before: %s\n", error_ptr); 
                }
                return 1; // 1 is error
        }
        
        *config = root; 
        
        free(json_string); 
        
        return 0; 
        
}

int handle_client2(int socket, int client){

        return 0; 
}

int readClientData2(char *buffer, int socket, cJSON *config, int fd){
        return 0; 
}

int startServer(int sfd, cJSON *config){
        printf("SFD: %d\n", sfd); 
        int new_fd; 
        struct sockaddr_storage peer_addr; 
        socklen_t peer_addrlen = sizeof(peer_addr);
        


        /* I don't think this checks to see if the client disconnects (need to implement that)*/
        while (1) {
                new_fd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addrlen);
                printf("new fd:  %d\n", new_fd);
                // char host[NI_MAXHOST], service[NI_MAXSERV];
                // nread = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addrlen);

                if (new_fd == -1) {
                        perror("accept failed");
                        continue;  // Ignore failed request
                }

                /* Using this one */
                // handle_client(&new_fd);
                printf("Handle Client Here\n"); 
                
                handle_client(new_fd, config);

                // gai = getnameinfo((struct sockaddr *) &peer_addr, peer_addrlen, host, NI_MAXHOST, service,
                //                 NI_MAXSERV, NI_NUMERICSERV);

                // if (gai == 0)
                //     printf("Received %zd bytes from %s:%s\n", nread, host, service);
                // else
                //     fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gai));
        }
        printf("Client disconnect\n"); 
        close(new_fd); 
        return 0; 
}