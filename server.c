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

ssize_t recv_all(int sockfd, void *buf, size_t n) {
        size_t total_received = 0;
        ssize_t bytes_received;
        char *ptr = (char*) buf; // Pointer to current position in buffer
    
        while (total_received < n) {
            bytes_received = recv(sockfd, ptr + total_received, n - total_received, 0);
    
            if (bytes_received == -1) {
                if (errno == EINTR) continue; // Interrupted by signal, try again
                perror("recv_all");
                return -1; // Real error
            } else if (bytes_received == 0) {
                // Peer disconnected gracefully
                fprintf(stderr, "recv_all: Peer disconnected during read.\n");
                return 0; // Indicate disconnection
            }
            total_received += bytes_received;
        }
        return total_received; // Should be equal to 'n' on success
    }

int readClientData(char *buffer, int socket){
        int offset = 0; 
        uint32_t json_size; 
        size_t buffsize = 10240; 
        

        printf("Json Size: %u\n",  json_size); 
        memcpy(&json_size, buffer + offset, sizeof(uint32_t)); 
        json_size = ntohl(json_size); 

        offset += sizeof(u_int32_t); 
        // Segmentation fault here
        // printf("json_size: %d\n", json_size); 
        char *json_string = malloc(json_size); 
        json_string = memcpy(json_string, buffer + offset, json_size);
        ssize_t hash_check; 
        
        printf("Header Bytes Received: %ld\n", sizeof(uint32_t) + json_size); 

        // printf("Json string: %s\n", json_string); 
        

        

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
        

        cJSON *_data_size = cJSON_GetObjectItemCaseSensitive(root, "size"); 
        double data_size = 0; 
        if(_data_size != NULL && cJSON_IsNumber(_data_size)){
                data_size = _data_size->valuedouble; 
                printf("Data size: %lf\n", data_size); 
        }else{
                fprintf(stderr, "Could not find 'size' or it's not a number.\n"); 
                return 1; 
        }
        
        
        
        
        double received = 0;  
        ssize_t numbytes; 
        char *newBuff = malloc(buffsize); 




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
        }
        
        

        free(newBuff);
        free(json_string); 



        
        return 0; 
}


int handle_client(int socket){
        printf("Server: Got connection on socket %d\n", socket); 
        ssize_t bytes_received; 
        int buffsize = BUF_SIZE;
        unsigned char test_hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};         
        int t = 0; 

                        
        int numbytes; 

        /* Check buffer for error */
        char *buffer = malloc(BUF_SIZE); 

        while(1){
                bzero(buffer, BUF_SIZE);
                printf("Waiting for client...\n");
                numbytes = recv(socket, buffer, BUF_SIZE, 0);
                printf("New Message\n");
                /* Maybe use recvmsg() with the struct msghdr  */

                /* An application can use select(2), poll(2), or epoll(7) to determine when more data arrives on a socket. */

                /* Client disconnects (not graceful)*/
                if (numbytes == -1) {
                        perror("recv");
                        close(socket);
                        break;

                } else if (numbytes == 0) { /* Graceful disconnect */
                        printf("Client disconnected gracefully (Socked FD: %d).\n", socket);
                        break;
                } 
                
                readClientData(buffer, socket); 
                
        }
        free(buffer); 

        return 0;
}

int startServer(int sfd){
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
                
                handle_client(new_fd);

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