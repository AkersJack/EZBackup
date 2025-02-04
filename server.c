#include <stdlib.h> 
#include <stdio.h>
#include <errno.h> 
#include <linux/limits.h>
#include <string.h> 
#include <pthread.h> 
#include <stdbool.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include <cjson/cJSON.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>

/* 


Compile the server 
gcc -g -D TEST_SERVER server.c -o server 

Compile with cjson: 
gcc -g -D TEST_SERVER server.c -o server -l cjson

Socket Documentation: 
https://man7.org/linux/man-pages/man2/socket.2.html
https://man7.org/linux/man-pages/man7/socket.7.html
    
TCP Documentation: 
https://man7.org/linux/man-pages/man7/tcp.7.html


getaddrinfo
https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    

getnameinfo()
https://man7.org/linux/man-pages/man3/getnameinfo.3.html


recvfrom()
https://man7.org/linux/man-pages/man3/recvfrom.3p.html

getsockname() 
https://man7.org/linux/man-pages/man2/getsockname.2.html


sendfile() 
https://man7.org/linux/man-pages/man2/sendfile.2.html

Socket Domains: 
    - For IPV4 we use AF_INET 
    - For IPV6 we use AF_INET6 



Socket Types: 
    SOCK_STREAM

Can also use the bitwise OR operator on the type argument for socket to modify behavior: SOCK_NONBLOCK
    SOCK_CLOEXEC


Socket Protocol: 



SOCK_STREAM
    - Full-duplex byte stream 
    - Must be in a connected state before any data can be sent or received on it. 
    - A connection to another socket is created with a conneect() call. 
    - Once connected, data may be transferred using read() and write() calls or some variant of the send() and recv() calls. 
    - When session ahs been completed a close() may be performed. 
    - SOCK_STREAM ensures that data is not lost or duplicated. 
    - If a piece of data for which the peer protocol has buffer space cannot be successfully transmitted within a 
    reasonable length of time then the connection is to be considered dead. 

    If SO_KEEPALIVE is enabled on the socket the protocol checks in a protocol-specific manner if the other end is still alive.
    
    A SIGPIPE signal is raised if a process sends or receives on a broken stream. 

    Socket Return values: 
        On success a file descriptor for the new socket is returned. 
        On error -1 is returned, and errno is set to indicate the error.


getaddrinfo()
    - Helps with setting up the socket 
    - AF_UNSPEC allows getaddrinfo() to return a socket address for either IPV4 or IPV6 (so either or can be used)


getnameinfo() 
    Converts a socket address to a corresponding host and service, in a protocol-independent manner. 


select() 
    the first argument should be the highest_numbered file descriptor in any of the sets plus 1. 
    select() checks all file descriptors from 0 up to this number minus 1.
    So if your highest fd is 5 you pass 6(5 + 1) to check fds 0 through 5. 
    select() monitors a range of file descriptors 
    
    
*/


#define BUF_SIZE 1024
#define MAX_BUFFER_SIZE 1048576 // 1 megabyte 
// #define MAX_BUFFER_SIZE 4096 //  
#define NUM_THREADS 2 // Defines the number of threads for the threadpool default is 16



// Used as a generic to return to the proper operation handler 
typedef void* (*OperationFunc)(void* , void*); 


// Contains all the possible operations (already defined in client.c)
typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 

// Task Structure 
typedef struct Task{
    void (*function)(void*); // A pointer to a function that returns void and takes 1 void pointer argument 
    void *argument; // Function argument
    struct Task *next; // Next task in queue
    

}Task;

struct MessageHeader{
    uint32_t operation; // Type of operation
    uint32_t size; // Size of the data coming in 
    uint32_t jsize; // Size of json data
    uint32_t fsize; // size of file/data
    
};

struct Message{
    uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
    uint32_t size; // Size of the entire payload 
    uint32_t jsize; // Size of json file 
    uint32_t fsize; // Size of the file/data
    // char payload[]; // File data and json data
    char *data;
};

// These handles should be made private (static) as they are different than the clients handles
// TODO: Implement this 
void* handle_message_transfer(void *sock_ptr, void *message_ptr){
    printf("Need to implement message transfer\n");

}


// Server-side check for incoming messages
int check_server_socket(int server_socket, int timeout_seconds){
    fd_set read_fs; 
    struct timeval timeout; 

    // Clear and set the socket set 
    FD_ZERO(&read_fs); 
    FD_SET(server_socket, &read_fs); 

    // Set timeout
    timeout.tv_sec = timeout_seconds; // sec 
    timeout.tv_usec = 0; // ms
    
    // Check if the socket is ready for reading 
    int ready = select(server_socket + 1, &read_fs, NULL, NULL, &timeout); 
    // int ready = select(server_socket + 1, &read_fs, NULL, NULL, NULL); 

    if (-1 == ready){
        perror("select error"); 
        return -1; 
    }else if (0 == ready){
        printf("Timeout occurred\n"); 
        return 0; 
    }

    return FD_ISSET(server_socket, &read_fs) ? 1 : 0; 
    
}


// int handle_file_transfer(void *sock, struct Message *mess, char *buff){
// int handle_file_transfer(void *sock, struct MessageHeader *mess, char *buff){
// At this point the header should have been fully read and message_ptr contains that data
void* handle_file_transfer(void *sock_ptr, void *message_ptr){
    int client_socket = *(int *)sock_ptr; 
    struct Message *message = (struct Message *) message_ptr; 
    // Check if a null-terminating character exists if not add one 
    char *jstring = malloc(message->jsize); 
    if(!jstring){
        perror("Failed to allocate memory");
        exit(1);
    }
    bzero(jstring, message->jsize);
    memcpy(jstring, message->data, message->jsize);
    if(jstring[message->jsize] != '\0'){
        jstring[message->jsize] = '\0';
    }
    // char *new_buffer = realloc(buffer, message->size); 
    ssize_t numbytes; 
    uint32_t buffsize = BUF_SIZE; // Holds the buffsize up to a certain point
    int header_csize = (BUF_SIZE - (sizeof(struct MessageHeader) + message->jsize)); // Size of file data in first header


    // printf("JSON String: %s\n", jstring);

    // cJSON *json_object = cJSON_Parse(jstring);
    // Just for testing
    //printf("File Data: %s\n", file_data);
    // Write to file here

    // Parse the json string and turn it into a json object (REMEMBER: DELETE THIS OBJECT WHEN DONE!)

    int counter = 0; // Counter for size

    // cJSON_Delete(json_object);
    // json_object = NULL; 
    bzero(jstring, message->jsize); 
    free(jstring); 
    jstring = NULL;

    
    // Allocate receive buffer
    size_t buffer_size = (message->fsize < MAX_BUFFER_SIZE) ? message->fsize : MAX_BUFFER_SIZE;
    char *buffer = malloc(buffer_size);
    bzero(buffer, buffer_size);
    if (!buffer) {
        perror("Failed to allocate buffer");
        return NULL;
    }
    
    // Track total bytes received 
    size_t total_received = 0; 
    

    // Receive loop 
    while (total_received < message->fsize){
        // Calculate remaining time to receive 
        size_t remaining = message->fsize - total_received; 
        size_t to_receive =  (remaining < buffer_size) ? remaining : buffer_size;
        
        // wait for socket to be ready 
        fd_set read_fds; 
        struct timeval timeout; 
        FD_ZERO(&read_fds); 
        FD_SET (client_socket, &read_fds); 
        timeout.tv_sec = 30; // 30 sec timeout
        timeout.tv_usec = 0; 
        
        int select_result = select(client_socket + 1, &read_fds, NULL, NULL, &timeout); 
        if(select_result <= 0){
            perror("select() failed or timed out"); 
            free(buffer); 
            return NULL; 
        }
        // Receive data in chunks 
        size_t bytes_received = 0; 
        while (bytes_received < to_receive){
            check_server_socket(client_socket, 1);
            if (total_received >= message->fsize) { // Check inside the loop
                break; // Exit the inner loop if done
            }
            ssize_t result = recv(client_socket, buffer + bytes_received, to_receive - bytes_received, 0); 
            if (result <= 0){
                if (result == 0){
                    printf("Connection closed by peer\n"); 
                }else{
                    perror("recv() failed"); 
                }
                free(buffer); 
                buffer = NULL; 
                return NULL;  
            }
            
            bytes_received += result; 
            total_received += result; 
            // printf("bytes_received: %lu\n", bytes_received);

        }
        
        // Process the received chunk here (write to file)
        
        // total_received += bytes_received; 
        printf("Progress: %zu/%u bytes\n", total_received, message->fsize);
    }
    
    printf("Successfully received: %u bytes\n", message->fsize);


    // Clean up 
    explicit_bzero(buffer, buffer_size); 
    free(buffer); 
    buffer = NULL; 
    

    // Now save the file 

}

OperationFunc getOperation(uint32_t op){
    OperationFunc *func;
    switch(op){
        case TEST_OPERATION:
            printf("Test Operation\n"); 
            // func = malloc(sizeof(handle_test));
            // return handle_test;
            break; // Technically don't need a break after a return but just in case. 
        case FILE_TRANSFER:
            // printf("File Transfer\n");
            // func = malloc(sizeof(handle_file_transfer)); 
            return handle_file_transfer;
            break;  
        case MESSAGE:
            printf("Message\n"); 
            // func = malloc(sizeof(handle_message_transfer)); 
            return handle_message_transfer;
            // return func;
            break;
        default: 
            printf("Invalid operation\n");
            return NULL;
            break;

    }
    
}



// TODO: Detect Endianness and handle accordingly for all floating point numbers
int serialize_MessageHeader(struct MessageHeader *s, char *buffer){
    uint32_t offset = 0; // Ensures memory is copied in the correct location
    
    // Serialize 'operation'
    uint32_t operation = htonl(s->operation);

    memcpy(buffer + offset, &operation, sizeof(uint32_t));

    


    uint32_t size = htonl(s->size);
    offset += sizeof(uint32_t); // Move to next memory location 
    memcpy(buffer + offset, &size, sizeof(uint32_t));
    
    
    return 0;  
}

typedef struct{

    // Array of thread IDs
    pthread_t *threads;  // Array of thread handles 
    size_t num_threads;  // Total number of threads
    Task *task_queue_rear; // Rear of the task queue
    Task *task_queue_front;  // Front of the task queue
    pthread_mutex_t task_queue_mutex; // Mutex for task queue access 
    pthread_cond_t task_queue_cond; // Condition variable for the task queue. 
    bool stop;  // Flag to stop the thread pool
    int qsize; // Size of queue

}ThreadPool; 


int threadpool_add_task(ThreadPool *pool, void (*function)(void*), void *argument){
    if (pool == NULL || function == NULL)
        return -1;
    
    // Create task
    Task *task = malloc(sizeof(Task));
    if (task == NULL)
        return -1; 

    task->function = function; 
    task->argument = argument; 
    task->next = NULL;  
    

    // Add task to queue
    pthread_mutex_lock(&pool->task_queue_mutex); 
    // If no tasks are in the queue
    if(pool->task_queue_rear == NULL){
        pool->task_queue_front = task; 
        pool->task_queue_rear = task;  
    }else{
        pool->task_queue_rear->next = task; 
        pool->task_queue_rear = task; 
    }

    pool->qsize++; 
    
    // Restarts one of the threads that are waiting on the condition variable cond. 
    // If no threads are waiting on cond, nothing happens. 
    // If several threads are waiting on cond, exactly one is restarted, but it is not specified which. 
    pthread_cond_signal(&pool->task_queue_cond);
    pthread_mutex_unlock(&pool->task_queue_mutex);
    

    return 0;  
}



void *worker_thread(void *arg){
    ThreadPool *pool = (ThreadPool*)arg; 
    Task *task;
    while (1) {
        /* 
         * If the mutex is locked by another thread it will suspend the calling thread until mutex is unlocked
         * If you don't want to block the calling threads use pthread_mutex_trylock
        */
        
        pthread_mutex_lock(&pool->task_queue_mutex); // Lock the mutex (or attempt to lock it)

        // Wait for task or stop signal 
        while (pool->task_queue_front == NULL && !pool->stop){
            pthread_cond_wait(&pool->task_queue_cond, &pool->task_queue_mutex);
        }
        
        // Check if thread pool is being stopped
        if(pool->stop && pool->task_queue_front == NULL){
            pthread_mutex_unlock(&pool->task_queue_mutex);
            break; 
        }

        // Get task from queue 
        printf("getting task from queue... \n");
        task = pool->task_queue_front; 
        pool->task_queue_front = task->next; 
        if (pool->task_queue_front == NULL){
            pool->task_queue_rear = NULL;
        }
        pool->qsize--;
        
        pthread_mutex_unlock(&pool->task_queue_mutex);
        

        // Execute task
        task->function(task->argument); 
        free(task); 
        task = NULL; 
        // printf("Done task\n");

        // if (EXIT == 1)
 
        //     break;
         
    }
    
    return NULL;
}

// Destroy the thread pool 
void threadpool_destroy(ThreadPool *pool){
    printf("Destroy Threadpool \n");
    if (pool == NULL)
        return; 
    
    pthread_mutex_lock(&pool->task_queue_mutex);
    pool->stop = 1; 

    //  Restarts all the threads that are waiting on the condition variable cond.
    pthread_cond_broadcast(&pool->task_queue_cond);
    pthread_mutex_unlock(&pool->task_queue_mutex);
    
    
    // Clean up remaining tasks 
    Task *current; 
    while (pool->task_queue_front != NULL){
        current = pool->task_queue_front;
        pool->task_queue_front = current->next; 
        free(current); 
        current = NULL; 
    }
    
    // Clean up thread pool resources
    pthread_mutex_destroy(&pool->task_queue_mutex);
    pthread_cond_destroy(&pool->task_queue_cond);
    free(pool->threads);
    pool->threads = NULL; 
    free(pool);
    pool = NULL;
}



ThreadPool *init_thread_pool(){
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    if (pool == NULL) 
        return NULL; 

    // pthread_t threads[NUM_THREADS]; // Array of threads 
    pool->threads = malloc(NUM_THREADS * sizeof(pthread_t));
    if (pool->threads == NULL){
        free(pool);
        pool = NULL; 
        return NULL; 
    }
    pool->num_threads = NUM_THREADS; 
    pool->task_queue_front = NULL;
    pool->task_queue_rear = NULL;
    pool->stop = 0;
    pool->qsize = 0; 
    
    pthread_attr_t attr; 
    pthread_attr_init(&attr);
    pthread_mutex_init(&pool->task_queue_mutex, NULL);
    for(int i = 0; i < NUM_THREADS; i++){

        /* 
         *
         * Creates a new thread 
         * arg1: pointer to new thread
         * arg2: thread attributes (NULL for default attributes)
         * arg3: function to call by new thread
         * arg4: arguments to the function the thread calls
         
        */
        printf("Creating thread %d\n", i);
        if(pthread_create(&(pool->threads[i]), &attr, worker_thread, pool) != 0){
            threadpool_destroy(pool); 
            return NULL;
        }
        
        /* 
         * Detaches a thread which means that resources are automatically released back 
         * To the system without the need for another thread to join with the 
         * terminated thread. 
        */

        pthread_detach(pool->threads[i]); // Could set this in the thread attr
    }
    
    pthread_attr_destroy(&attr);
    return pool;
    

}

// int deserialize_header(struct MessageHeader *mess){
int deserialize_header(struct Message *mess){
    mess->operation = ntohl(mess->operation); 
    mess->size = ntohl(mess->size);
    mess->jsize = ntohl(mess->jsize);
    mess->fsize = ntohl(mess->fsize); 
    
    return 0; 
}



//void handle_client(int client_socket){
void handle_client(void *sock){
    int client_socket = *((int*) sock); 
    printf("server: got connection on socket %d\n", client_socket);
    // char buffer[BUF_SIZE]; 
    ssize_t bytes_received; 
    int buffsize = BUF_SIZE; 
    
    

    // struct MessageHeader *mess = (struct MessageHeader *)malloc(sizeof(struct MessageHeader));
    // mess->operation = OPERATION_TEST; 
    // mess->size = 1000; 
    // struct Message *client_message = (struct Message *)malloc(sizeof(struct Message));
    struct Message *client_message = malloc(sizeof(struct Message));
    // struct MessageHeader *client_message = malloc(sizeof(struct MessageHeader));
    int offset = 0;
    int numbytes; 
    // char *buffer = malloc(BUF_SIZE);
    char *buffer = malloc(BUF_SIZE);
    int sock_check; 
    int t = 0;
    while(1){
        bzero(buffer, BUF_SIZE);
        if(!buffer){
            perror("malloc");
            exit(1);
        }
        buffsize = BUF_SIZE; 
        offset = 0; 
        // Receive data
        // sock_check = check_server_socket(client_socket, 1);
        // printf("Sock check (After): %d\n", sock_check);
        printf("Waiting for client...\n");
        numbytes = recv(client_socket, buffer, BUF_SIZE, 0);
        if(numbytes == -1){
            perror("recv"); 
            close(client_socket); 
            break;
        }
        else if(numbytes == 0){
            printf("Client disconnected gracefully (Socked FD: %d).\n", client_socket);
            break;
        }

      

      
        // buffer[numbytes] = '\0'; 
        // printf("server received: '%s'\n", buffer); 
        
        // Read what the client sent 
        memcpy(&client_message->operation, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->size, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->jsize, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&client_message->fsize, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    
        // printf("sizeof message header: %lu\n", sizeof(struct MessageHeader));
        deserialize_header(client_message);
        
        

        printf("Operation: %u\nSize: %u\nJsize: %u\nFsize: %u\n", client_message->operation, client_message->size, client_message->jsize, client_message->fsize);
        // printf("Buffer: %s\n", buffer + sizeof(struct MessageHeader));

        if(client_message->operation > 3){
            printf("Error here \n"); 
        }

        client_message->data = buffer + offset; 
        OperationFunc selectedOP = getOperation(client_message->operation); 
        selectedOP(sock, client_message);

        
        // If the client is sending a file 
        // if(client_message->operation == FILE_TRANSFER){
            // handle_file_transfer(&client_socket, client_message);
            
            // char *jstring = malloc(client_message->jsize + 1); 

            // memcpy(jstring, buffer + offset, client_message->jsize);
            // printf("JSON String: %s\n", jstring);

            // // Parse the json string and turn it into a json object (REMEMBER: DELETE THIS OBJECT WHEN DONE!)
            // cJSON *json_object = cJSON_PARSE(jstring);

            // offset += client_message->jsize; // Skip the json 
            // free(jstring); 
            // cJSON_Delete(json_object);
            // handle_file_transfer(&client_socket, client_message, buffer + sizeof(struct MessageHeader));
        // }

        




        // Send response
        const char *msg = "Hello from server!"; 
        check_server_socket(client_socket, 1);
        // char *msg = client_message; 
        if(send(client_socket, msg, strlen(msg), 0) == -1){
        // if(send(client_socket, m_buffer, 128, 0) == -1){
         perror("send"); 
        }


     
        // if(send(client_socket, "ACK", 3, MSG_NOSIGNAL) < 0){
        // if(send(client_socket, "ACK", 3, MSG_NOSIGNAL) < 0){
        //     if(errno = EPIPE){
        //         printf("Client disconnected (broken pipe) (Socket FD: %d)\n", client_socket);
        //         break;
        //     }
        // }
        
    }
    explicit_bzero(buffer, BUF_SIZE); 
    free(buffer); 
    buffer = NULL;
    // free(mess);
    // free(m_buffer);
    explicit_bzero(client_message, sizeof(struct Message));
    free(client_message);
    client_message = NULL; 
    close(client_socket); 

}


#ifdef TEST_SERVER
int main(int argc, char *argv[]){

    printf("Server started\n"); 

    // argv1 is port 

    if (argc != 2){
        fprintf(stderr, "Usage: %s port \n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    int gai, sfd, new_fd; 
    char buf[BUF_SIZE];
    ssize_t nread; 
    socklen_t peer_addrlen; 
    struct addrinfo hints; 
    struct addrinfo *result, *rp;
    struct sockaddr_storage peer_addr; 
    struct sockaddr_in server_addr;
    socklen_t server_addrlen = sizeof(server_addr);
    


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // ALlow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // Socket Stream
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol 
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    
    gai = getaddrinfo(NULL, argv[1], &hints, &result);
    if ( gai != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        exit(EXIT_FAILURE);
    }
    /* 
     * getaddrinfo() returns a list of address structures. 
        Try each address until we successfully bind(2). 
        If socket(2) (or bind(2)) fails, we close the socket
        and try the next address.  
    */
    
    for (rp = result; rp != NULL; rp = rp->ai_next){
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); 
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0){
            getsockname(sfd, (struct sockaddr *)&server_addr, &server_addrlen); 
            char ip_str[INET_ADDRSTRLEN];
            printf("Socket bound at address: %s:%d\n", ip_str, ntohs(server_addr.sin_port));
            break;  /* Success */
        } 
        // if(bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1){
        //     perror("server: bind"); 
        //     close(sfd);
        //     continue; 
        // }
        // break;
        close(sfd); 
    }
    
    freeaddrinfo(result); /* No longer needed */
    

    if (rp == NULL){ /* NO address succeeded*/
        fprintf(stderr, "Could not bind\n"); 
        exit(EXIT_FAILURE);
    }
    

    
    if(listen(sfd, 10) == -1){
        perror("listen"); 
        close(sfd); 
        exit(1);
    }
    printf("server: waiting for connections...\n");
    
    ThreadPool *pool = init_thread_pool(); 
    peer_addrlen = sizeof(peer_addr);

    while(1){
        new_fd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addrlen); 
        printf("new fd:  %d\n", new_fd);
        // char host[NI_MAXHOST], service[NI_MAXSERV]; 
        // nread = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addrlen);
        
        
        
        
        if (new_fd == -1){
            perror("accept failed");
            continue; // Ignore failed request 
        } 
        

        // printf("Adding new task \n"); 
        // if (EXIT){
        //     printf("Exiting...\n");
        //     break; 
            
        // }
        threadpool_add_task(pool, &handle_client, &new_fd);
        printf("Queue size: %d\n", pool->qsize);
        // handle_client(new_fd);

        

        
        // gai = getnameinfo((struct sockaddr *) &peer_addr, peer_addrlen, host, NI_MAXHOST, service,
        //                 NI_MAXSERV, NI_NUMERICSERV);
    

        // if (gai == 0)
        //     printf("Received %zd bytes from %s:%s\n", nread, host, service); 
        // else
        //     fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gai));


    
    }

    printf("At main end\n");
    close(new_fd);
    close(sfd);
    // threadpool_destroy(pool);
    return 0;
}

#endif