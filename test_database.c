#include "database.h"
#include "tools.h"
#include <linux/limits.h>
#include <stdlib.h>

/*
gcc -g test_database.c database.c tools.c -o database -l sqlite3

*/

int main(int argc, char *argv[]){
        
        // Return code
        int rc; 

        sqlite3 *db; 
        
        char db_name[] = "database.db"; 
        
        char file[] = "./test_database.c";
        
        if(init_Database(&db, db_name)){
                printf("Error: Failed to open/create the database %s\n", db_name);
                sqlite3_close(db); 
                return 1; 
        }
        
        // if(sqlite3_open("database.db", &db) != SQLITE_OK){
        //         fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        //         sqlite3_close(db); 
        //         return 1; 
        // } 
        
        struct stat sta; 
        lstat(file, &sta); 
        char real_path[PATH_MAX];
        
        
        char file_name[sizeof(file)]; 
        strcpy(file_name, file);
        
        dbItem item; 
        
        realpath("./test_database", real_path);
        
        item.path = real_path; 
        item.s = &sta; 
        item.name = getFname(file_name);
        printf("Item name: %s\n", item.name);

        int err = createTable(db, "Test");
        

        if(addItem(db, "Test", &item)){
                printf("Error: Unable to add item to the database.\n");
        }else{
                printf("item added to the database\n");
        }
        

        showTableItems(db, "Test");



        printf("Closed database successfully\n"); 
        sqlite3_close(db); 



        

        return 0;
}