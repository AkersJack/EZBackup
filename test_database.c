#include "database.h"
#include "tools.h"
#include <linux/limits.h>
#include <stdlib.h>
#include "config.h"

/*
gcc -g test_database.c database.c tools.c config.c -o database -l sqlite3 -l cjson

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
        
        realpath(file, real_path);
        
        item.path = real_path; 
        item.s = &sta; 
        item.name = getFname(file_name);
        printf("Item name: %s\n", item.name);

        char tn[25]; 
        getTableName(db, tn);
        printf("New Table Name: %s\n", tn); 

        // int err = createTableData(db, "T1");
        int err = createTableData(db, tn);
        

        if(addItem(db, tn, &item)){
                printf("Error: Unable to add item to the database.\n");
        }else{
                printf("item added to the database\n");
        }
        

        // showTableItems(db, "Test");
        
        /* Testing getItems_path */
        struct dbObjNode *node; 
        node = malloc(sizeof(struct dbObjNode));
        getItems_path(db, tn, real_path, node);

        struct dbObjNode *tmp = node; 
        // while(node->next != NULL){
        //         printf("Size: %d\n", node->size);
        //         printf("created: %s\n", node->item->created);
        //         printf("Item: %s\n", node->item->name);
        //         printf("Path: %s\n", node->item->path);
        //         printf("st_dev: %lli\n",node->item->st_dev); 
        //         printf("st_ino: %lli\n",node->item->st_ino); 
        //         printf("st_mode: %lli\n",node->item->st_mode); 
        //         printf("st_nlink: %lli\n",node->item->st_nlink); 
        //         printf("st_uid: %lli\n",node->item->st_uid); 
        //         printf("st_gid: %lli\n",node->item->st_gid); 
        //         printf("st_rdev: %lli\n",node->item->st_rdev); 
        //         node = node->next;
        // }
        node = tmp; 



        freeNodes(node);

        /* Testing getItems() */
        
        node = malloc(sizeof(struct dbObjNode));
        getItems(db, tn, item.name, real_path, node);

        tmp = node; 
        while(node->next != NULL){
                printf("Size: %d\n", node->size);
                printf("created: %s\n", node->item->created);
                printf("Item: %s\n", node->item->name);
                printf("Path: %s\n", node->item->path);
                printf("st_dev: %lli\n",node->item->st_dev); 
                printf("st_ino: %lli\n",node->item->st_ino); 
                printf("st_mode: %lli\n",node->item->st_mode); 
                printf("st_nlink: %lli\n",node->item->st_nlink); 
                printf("st_uid: %lli\n",node->item->st_uid); 
                printf("st_gid: %lli\n",node->item->st_gid); 
                printf("st_rdev: %lli\n",node->item->st_rdev); 
                node = node->next;
        }
        node = tmp; 



        freeNodes(node);

        /*
        printf("\033[31mRed text\033[0m\n"); // Red text
        printf("\033[32mGreen text\033[0m\n"); // Green text
        printf("\033[33mYellow text\033[0m\n"); // Yellow text
        printf("\033[34mBlue text\033[0m\n"); // Blue text
        printf("\033[35mMagenta text\033[0m\n"); // Magenta text
        printf("\033[36mCyan text\033[0m\n"); // Cyan text
        printf("\033[37mWhite text\033[0m\n"); // White text

        printf("\033[41mRed background\033[0m\n"); // Red background
        printf("\033[92mBright Green text\033[0m\n");
        printf("\033[104mBright Blue background\033[0m\n");
    
        printf("\033[31;43mRed text on yellow background\033[0m\n"); // Combined colors

        */

        // printf("\n");
        // removeOldItem(db, "Test", item.name, real_path);

        // printf("\n");
        // showTableItems(db, "Test");

        buildConfig();
        
        createTableParent(db); 
 
        showTableItems(db, "T1"); 

        cJSON *root; 
        readConfig(&root); 
        
        char *json_string = cJSON_Print(root); 
        printf("%s\n", json_string); 
        
        cJSON *remote_item = cJSON_GetObjectItemCaseSensitive(root, "remote_addr"); 

        printf("Remote address (from config.json): %s\n", remote_item->valuestring);
        
        
        cJSON_Delete(root); 
        




        sqlite3_close(db); 
        printf("Closed database successfully\n"); 


        

        return 0;
}