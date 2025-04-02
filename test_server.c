#include "server.h"
#include "config.h"
#include <netdb.h>



int main(int argc, char *argv[]){


        char buf[BUF_SIZE]; 
        ssize_t nread; 
        socklen_t peer_addrlen; 
        struct addrinfo hints; 
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;      // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM;  // Socket Stream
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;  // TCP protocol
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;
        
        
        printf("Server Ran!\n");

        return 0; 
}