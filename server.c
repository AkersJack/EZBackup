/* 
        Essentially a refined version of server_NT.c
*/

#include "server.h"



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
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;  // TCP protocol
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

int readClientData(char *buffer){
        int offset = 0; 
        uint32_t json_size; 
        

        memcpy(&json_size, buffer + offset, sizeof(uint32_t)); 
        json_size = ntohl(json_size); 
        offset += sizeof(u_int32_t); 
        char *json_string; 
        json_string = buffer + offset; 

        printf("Json string: %s\n", json_string); 
        

        
        printf("Json Size: %u\n",  json_size); 

        
        /* 
         * Read Json Data here
        */
        cJSON *root = cJSON_Parse(json_string);
        




        
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
                
                readClientData(buffer); 
                
        }

        return 0;
}

int startServer(int sfd){
        printf("SFD: %d\n", sfd); 
        int new_fd; 
        struct sockaddr_storage peer_addr; 
        socklen_t peer_addrlen; 

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