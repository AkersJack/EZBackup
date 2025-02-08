#ifndef CLIENT_H 
#define CLIENT_H

#include <sys/socket.h> 
#include <netdb.h> 


#endif


struct Message{
        uint32_t operation; // Operation Type (e.g., FILE_TRANSFER, RECOVERY)
        uint32_t size; // Total size of the payload/message 
        uint32_t dsize; // Data size (size of data associated with this packet)
        uint32_t jsize; // Size of json file (if included)
        uint32_t total_transfered; // Total amount of data transfered (can be NULL)
        char *data; // JSON data but can be NULL for no data
};

typedef void* (*OperationFunc)(void* , void*); 

typedef enum{
    TEST_OPERATION, 
    FILE_TRANSFER, 
    MESSAGE, 
}Operation; 




typedef struct{
    uint32_t upper;  // Upper half of a uint64_t
    uint32_t lower; // Lower half of a uint64_t
}uint64_s;

uint64_s split_u64(uint64_t val); 



uint64_t combine_u32(uint32_t upper, uint32_t lower);



unsigned char* genHash(const char *fpath);