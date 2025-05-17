#include "server.h"
#include "config.h"
#include <netdb.h>
#include <sys/socket.h> 


/*
 * Pass config settings or cjson pointer to functions so config settings can be read 
*/
int main(int argc, char *argv[]){

        cJSON *config = cJSON_CreateObject(); 
        readConfig(&config);

        cJSON *cjson_port = cJSON_GetObjectItemCaseSensitive(config, "port");
        char *port = cjson_port->valuestring;
        printf("Port: %s\n", port);

        int sfd = 0; 

        initServer(port, &sfd);
        printf("Socket: %d\n", sfd); 
        startServer(sfd, config); 


        // close(new_fd); 
        close(sfd); 
        cJSON_Delete(config); 
        printf("Server Ran!\n");

        return 0; 
}