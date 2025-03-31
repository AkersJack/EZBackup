#include "database.h"
#include <stdlib.h>

/* 
        The table that gets created should have the same name as the file 
        that is written to disk. 
        

        The directory structure and the files saved within the archives is 
        what gets written to the actual table. (essentially stat command stuff)



*/




// Number of copies of a single file to keep 
#define COPY_NUM 5


static int table_callback(void *data, int argc, char **argv, char **azColName){
        char *tableName = data; 
        // printf("Tables in DB: \n");
        for (int i = 0; i < argc; i++){
                // This could cause an issue if the tableName was made to be super long
                if(strncmp(tableName, argv[i], strlen(tableName)) == 0){
                        // We found what we need
                        return 1; 
                }
                // printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        return 0; 
}

int checkTableName(sqlite3 *db, char *tableName){
        int rc; 
        char *error_msg;  
        
        const char *sql; 
        
        sql = "SELECT name FROM sqlite_master WHERE type='table';";
        
        rc = sqlite3_exec(db, sql, table_callback, tableName, &error_msg);
        
        if (rc == SQLITE_ABORT){
                return 0; 
        }

        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL checkTableName() error: %s\n", error_msg); 
                sqlite3_free(error_msg); 
        }
        return 1; 
        
}

int removeOldItem(sqlite3 *db, char *tableName, char *name, char *path){
        sqlite3_stmt *stmt; 
        int rc; 
        char *err_msg; 
        // char sql_select[] = "SELECT id FROM ? WHERE path = '?' AND name = '?' ORDER BY created_at ASC LIMIT 1;";
        char *sql_select; 
        size_t sql_select_size; 

        sql_select_size = strlen("SELECT id FROM WHERE path = ? AND name = ? ORDER BY created_at ASC LIMIT 1;") + strlen(tableName) + 2;
        sql_select = malloc(sql_select_size);

        if (checkTableName(db, tableName)){
                fprintf(stderr, "Error table %s doesn't exist in %s.\n", tableName, "database.db");
                free(sql_select); 
                return 1; 
        }
        
        snprintf(sql_select, sql_select_size, "SELECT id FROM %s WHERE path = ? AND name = ? ORDER BY created_at ASC LIMIT 1;", tableName);
        // char *sql_select = "SELECT id FROM Test WHERE path = ? AND name = ? ORDER BY created_at ASC LIMIT 1;";

        // char *sql = malloc(sql_size);
        // char *sql_select = malloc(sql_select_size);
        int oldest_id = -1; 

        
        rc = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL removeOldItem BEGIN TRANSACTION error: %s\n", err_msg);
                sqlite3_free(err_msg);
                return 1; 
        }
        
        // Used to select the item 
        // snprintf could cause problems with sql injections (CHANGE IT)
        // snprintf(sql_select, sql_select_size, "SELECT id FROM %s WHERE path = '%s' AND name = '%s' ORDER BY created_at ASC LIMIT 1;", tableName, path, name);
        rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL removeOldItem BEGIN TRANSACTION error: %s\n", err_msg);
                sqlite3_free(err_msg);
                return 1; 
        }
        
        if(rc == SQLITE_OK){
                sqlite3_bind_text(stmt, 1, path, strlen(path), SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_TRANSIENT);
                if(sqlite3_step(stmt) == SQLITE_ROW){
                        oldest_id = sqlite3_column_int(stmt, 0);
                        printf("Found oldest record with ID: %d\n", oldest_id);
                } else {
                        printf("No records found in the table.\n");
                }
        }else{
                fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        }
        
        sqlite3_finalize(stmt);
        
        


        if(oldest_id != -1){
                sqlite3_stmt *deleteStmt;

                // Used to delete the item
                char *sql;
                size_t sql_size = strlen("DELETE FROM ? WERE ID = ?;") + strlen(tableName) + 2;                
                sql = malloc(sql_size);
                snprintf(sql, sql_size, "DELETE FROM %s WHERE id = ?;", tableName);
                // printf("SQL Statement: %s\n", sql); 
                
                rc = sqlite3_prepare_v2(db, sql, -1, &deleteStmt, NULL); 
                if (rc == SQLITE_OK){
                        sqlite3_bind_int(deleteStmt, 1, oldest_id);
                        rc = sqlite3_step(deleteStmt);
                        if (rc == SQLITE_DONE){
                                printf("Successfully deleted id %d\n", oldest_id);
                        }else{
                                fprintf(stderr, "Failed to deleted record (id %d): %s\n", oldest_id, sqlite3_errmsg(db));
                                return 1;
                        }
                        
                }
                
                sqlite3_finalize(deleteStmt);
                free(sql); 
        }
        

        rc = sqlite3_exec(db, "COMMIT", NULL, NULL, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL removeOldItem COMMIT error: %s\n", err_msg);
                sqlite3_free(err_msg);
                return 1; 
        }
        
        

        return 0; 
}

time_t parseTime(const char *datetime){
        struct tm tm_struct = {0}; 
        
        time_t time_val; 
        return time_val;
}

int addItem(sqlite3 *db, char *tableName, dbItem *item){

        struct dbObjNode *node; 
        struct dbObjNode *tmp; 
        int num_items = 0; 
        
        node = malloc(sizeof(struct dbObjNode));
        getItems(db, tableName, item->name, item->path, node);
        tmp = node; 
        

        while(tmp->next != NULL){
                tmp = tmp->next; 
                num_items++; 
        }
        
        if(num_items == COPY_NUM){
                freeNodes(node);
                printf("Item %s at %s already exists max item copies allowed in database is %d.\n", item->name, item->path, COPY_NUM);
                return 1;                  
        }
        printf("Num items: %d\n", num_items);
        
        /* Means item already exists */
        // if(node->item != NULL){
        //         freeNodes(node);
        //         printf("Item %s at %s already exists.\n", item->name, item->path);
        //         return 1;                 
        // }



        sqlite3_stmt *stmt; 


        long long device_id = (long long)item->s->st_dev; 
        long long inode_num = (long long)item->s->st_ino; 
        long long protection = (long long)item->s->st_mode; 
        long long num_hard_links = (long long)item->s->st_nlink; 
        long long owner_uid = (long long)item->s->st_uid; 
        long long owner_gid = (long long)item->s->st_gid; 
        long long dev_id = (long long)item->s->st_rdev;
        long long size = (long long)item->s->st_size;
        long long blocksize = (long long)item->s->st_blksize;
        long long blocks = (long long)item->s->st_blocks;
        long long last_access = (long long)item->s->st_atime;
        long long last_mod = (long long)item->s->st_mtime;
        long long last_status = (long long)item->s->st_ctime;
        char sql[512];
        /*
         * Check if the item already exists if it does return the proper error code
         * Maybe make a version of the function that will do multiple copies
         * these copies will work off of date/time 
        */

        
        // Here Test is the table name 
        // Add time into sql statement
        
        snprintf(sql, sizeof(sql), "INSERT INTO %s ("
                                        "name,"
                                        "path,"
                                        "st_dev," 
                                        "st_ino," 
                                        "st_mode," 
                                        "st_nlink," 
                                        "st_uid," 
                                        "st_gid," 
                                        "st_rdev," 
                                        "st_size," 
                                        "st_blksize," 
                                        "st_blocks," 
                                        "st_atime," 
                                        "st_mtime," 
                                        "st_ctime" 
                                        ")"
                                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);", tableName);
        


        printf("SQL: %s\n", sql); 
        // printf("Item->name: %s\n", item->name);
        // printf("Item->path: %s\n", item->path);

        if(sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL) != SQLITE_OK){
                fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                return 1; 
                
        }

        sqlite3_bind_text(stmt, 1, item->name, strlen(item->name), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, item->path, strlen(item->path), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3,  device_id);
        sqlite3_bind_int64(stmt, 4,  inode_num);
        sqlite3_bind_int64(stmt, 5,  protection);
        sqlite3_bind_int64(stmt, 6, num_hard_links);
        sqlite3_bind_int64(stmt, 7, owner_uid);
        sqlite3_bind_int64(stmt, 8, owner_gid);
        sqlite3_bind_int64(stmt, 9, dev_id);
        sqlite3_bind_int64(stmt, 10, size);
        sqlite3_bind_int64(stmt, 11, blocksize);
        sqlite3_bind_int64(stmt, 12, blocks);
        sqlite3_bind_int64(stmt, 13, last_access);
        sqlite3_bind_int64(stmt, 14, last_mod);
        sqlite3_bind_int64(stmt, 15, last_status);

        printf("%s\n", sql);

        
        int rc; 

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE){
                fprintf(stderr, "SQL INSERT error: %s\n", sqlite3_errmsg(db));
                sqlite3_finalize(stmt); // Finalize the statement even if there is an error
                return 1; 
                
        }
        sqlite3_finalize(stmt); // Finalize the statement on success
        return 0; 
}


/*
        Show all the items that are within a table
        (database needs to be opened already )
*/ 

static int query_callback(void *data, int argc, char **argv, char **azColName){
        for (int i = 0; i < argc; i++){
                // argv[i] ? argv[i] : "NULL" checks if the argv[i] value is null if not use the value
                printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL"); 
                
        }
        printf("\n");
        return 0;
}

static int query_callback_obj(void *data, int argc, char **argv, char **azColName){
        struct dbObjNode *node = data; 

        dbObj *obj; 
         

        
        
        
        /*
         * Create node 
         * create new dbobj and fill out obj
         * jump to tail and assign next value to new obj
         * set tail to new node (thus updating tail and end of the list) 
        */

        
        // Create a function to assign values to the obj
        obj = malloc(sizeof(dbObj));
        while (node->next != NULL){
                node = node->next;  
        }

        struct dbObjNode *new_node; 
        
        
        char *name; 
        char *path; 
        char *created;
        
        /* Strings are guaranteed null terminated in sqlite3*/
        created = malloc(strlen(argv[1]) + 1);
        name = malloc(strlen(argv[2]) + 1);
        path = malloc(strlen(argv[3]) + 1);
        
        // Could probably use strncpy() 
        memcpy(created, argv[1], strlen(argv[1]) + 1);
        memcpy(name, argv[2], strlen(argv[2]) + 1);
        memcpy(path, argv[3], strlen(argv[3]) + 1);


        new_node = malloc(sizeof(struct dbObjNode));
        node->item = obj;
        node->next = new_node; 
        new_node->item = NULL; 
        new_node->next = NULL;
        node->size++;
        new_node->size = node->size;

        obj->id = atoi(argv[0]);
        obj->created = created;
        obj->name = name;
        obj->path = path;
        obj->st_dev = (long long)atoi(argv[4]);
        obj->st_ino = (long long)atoi(argv[5]);
        obj->st_mode = (long long)atoi(argv[6]);
        obj->st_nlink = (long long)atoi(argv[7]);
        obj->st_uid = (long long)atoi(argv[8]);
        obj->st_gid = (long long)atoi(argv[9]);
        obj->st_rdev = (long long)atoi(argv[10]);
        obj->st_size = (long long)atoi(argv[11]);
        obj->st_blksize = (long long)atoi(argv[12]);
        obj->st_blocks = (long long)atoi(argv[13]);
        obj->st_Atime = (long long)atoi(argv[14]);
        obj->st_Mtime = (long long)atoi(argv[15]);
        obj->st_Ctime = (long long)atoi(argv[16]);

        // printf("Name: %s\n", obj->name);
        // printf("Created on: %s\n", argv[1]);
        // printf("Path: %s\n", obj->path);
        // printf("Obj ID: %s\n", argv[0]);
        // printf("Obj name: %s\n", obj->name);
        // printf("Obj path: %s\n", obj->path);
        


        // for (int i = 0; i < argc; i++){

                
                // argv[i] ? argv[i] : "NULL" checks if the argv[i] value is null if not use the value
                // printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL"); 
                

        // }
        
        // for (int i = 0; i < dbObjs->size; i++){
        //         dbObj *dbItem2;
        //         memcpy(dbItem2, dbObjs->obj_list[i * 8], 7); 
        //         printf("DbItem2: %p\n", (void *)dbItem2);
        // }

        // printf("\n");
        return 0;
}

int showTableItems(sqlite3 *db, char *tableName){
        // char baseString[] = "SELECT * FROM "; 
        // char *sql = malloc(strlen(baseString) + strlen(tableName) + 2);
        char *sql; 
        size_t sql_size = sizeof(tableName) + 25; 
        if (checkTableName(db, tableName)){
                fprintf(stderr, "Error table %s doesn't exist in %s.\n", tableName, "database.db");
                return 1; 
        }
        sql = malloc(sql_size);
        
        snprintf(sql, sql_size, "SELECT * FROM %s;", tableName);
        
        char *err_msg; 
        int rc; 
        
        rc = sqlite3_exec(db, sql, query_callback, NULL, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL error showTableItems(): %s\n", err_msg);
                sqlite3_free(err_msg);
                free(sql);
                return 1; 
        }
        printf("%s\n", sql);

        free(sql);
        return 0; 
}

int freeNodes(struct dbObjNode *node){
        struct dbObjNode *tmp; 
        
        int n_freed = 0;  
        while(node->next != NULL){
                // Free Obj 
                free(node->item->created);
                node->item->created = NULL;
                free(node->item->name);
                node->item->name = NULL; 
                free(node->item->path);
                node->item->path = NULL;
                free(node->item);
                node->item = NULL; 

                
                // Free Node; 
                tmp = node; 
                node = node->next; 
                free(tmp);
                tmp = NULL; 
                n_freed++;
                
        }
        
        free(node->item);
        node->item = NULL; 
        free(node); // Last free
        node = NULL; 
        n_freed++; 
        return 0; 
}



/* Could change this so it is a selection function so it gets whatever options are selected */
int getItems_path(sqlite3 *db, char *table_name, char *path, struct dbObjNode *node){

        // struct dbObjNode *node; 
        

        // Gonna need a custom free function for this 
        
        node->size = 0; 
        node->next = NULL; 
        node->item = NULL; 

        // The default text shouldn't be longer than 50 characters
        size_t sql_size = strlen(path) + strlen(table_name) + 50; 

        // Error check this
        char *sql = malloc(sql_size);
        if(checkTableName(db, table_name)){
                printf("Error table %s does not exist (getItems_path).\n", table_name);
                return 1; 
        }
        snprintf(sql, sql_size, "SELECT * FROM %s WHERE path = '%s';", table_name, path);
        printf("SQL: %s\n", sql); 
        
        int rc; 
        char *err_msg; 

        rc = sqlite3_exec(db, sql, query_callback_obj, node, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL getItems_path error: %s\n", err_msg);
                sqlite3_free(err_msg);
                free(sql);
                // Custom dbObjs Free here
                return 1; 
        }
        


        //printf("SQL Path: %s\n", sql);
        free(sql);
        return 0;
                
}



int getItems(sqlite3 *db, char *table_name, char *name, char *path, struct dbObjNode *node){

        // struct dbObjNode *node; 
        

        // Gonna need a custom free function for this 
        
        node->size = 0; 
        node->next = NULL; 
        node->item = NULL; 

        // The default text shouldn't be longer than 50 characters
        size_t sql_size = strlen(path) + strlen(table_name) + strlen(name) + 50; 

        // Error check this
        char *sql = malloc(sql_size);

        snprintf(sql, sql_size, "SELECT * FROM %s WHERE path = '%s' AND name = '%s';", table_name, path, name);
        
        int rc; 
        char *err_msg; 

        rc = sqlite3_exec(db, sql, query_callback_obj, node, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL getItems() error: %s\n", err_msg);
                sqlite3_free(err_msg);
                free(sql);
                // Custom dbObjs Free here
                return 1; 
        }
        


        //printf("SQL Path: %s\n", sql);
        free(sql);
        return 0;
                
}

int init_Database(sqlite3 **db, char *filename){
        // Creates the file if it does not already exist 
        if(sqlite3_open(filename, db) != SQLITE_OK){
                fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
                sqlite3_close(*db); 
                return 1; 
        } 
        printf("Database opened successfully\n");
        return 0; 
}


static int gtn_callback(void *data, int argc, char **argv, char **azColName){
        char *name = data; 
        int num; 
        for(int i = 0; i < argc; i++){
                if(strcmp(azColName[i], "name") == 0){
                        if(argv[i] != NULL && argv[i][0] == 'T'){
                                char *number = malloc(strlen(argv[i])); 
                                // memmove(number, argv[i] + 1, strlen(argv[i]));
                                strcpy(number, argv[i] + 1); 
                                
                                // Check to ensure the table is a data table and not another table (may be possible)
                                if((num = atoi(number)) != 0){
                                        num++;
                                        snprintf(name, 25, "T%d", num); 
                                }
                                        
                                free(number);
                                
                        }
                }
        }
        
        return 0; 
}

int getTableName(sqlite3 *db, char *tableName){
        *tableName = '\0'; 
        char *errMsg; 
        int rc; 
        char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'T%';"; 
        rc = sqlite3_exec(db, sql, gtn_callback, tableName, &errMsg); 
        if(rc != SQLITE_OK){
                fprintf(stderr, "SQL error %s\n", errMsg); 
                sqlite3_free(errMsg); 
        }
        if(tableName[0] == '\0'){
                printf("No Data tables found creating table T1\n"); 
                snprintf(tableName, 25, "T1"); 
        }
        return 0; 

        
} 

int createTableParent(sqlite3 *db){
        char buffer[1024]; 
        
        snprintf(buffer, sizeof(buffer),
                        "CREATE TABLE IF NOT EXISTS parent (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                        "tableName TEXT NOT NULL,"
                        "lastBackup DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                        ");"
        ); 
        char *errMesg; 
        int err; 
        if((err = sqlite3_exec(db, buffer, NULL, NULL, &errMesg)) != SQLITE_OK){
                fprintf(stderr, "SQL error: %s\n", errMesg);
                // printf("Error: %d\n", err);
                sqlite3_free(errMesg);
                return err; 
        }
        printf("Parent table created successfully\n");
        
        return 0; 
}

int createTableData(sqlite3 *db, char* tableName){

        char buffer[1024];
        // time is the datetime of when that item was backed-up (last backup)
        /*
         * ADD
        * time DATETIME NOT NULL, 
        */
         
        
        if (tableName == NULL){
                
                char tn[25];
                getTableName(db, tn);  
                printf("Name: %s\n", tn); 
        }
        // Need to implement these two things
        // Archive is which item in the parent archive the item is stored in (when we split up archives)
        // parchive is the parent archive (again if we split up archives)
        snprintf(buffer, sizeof(buffer), 
                "CREATE TABLE %s (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP, \
                name TEXT NOT NULL, \
                path TEXT NOT NULL, \
                st_dev INTEGER NOT NULL, \
                st_ino INTEGER NOT NULL, \
                st_mode INTEGER NOT NULL, \
                st_nlink INTEGER NOT NULL, \
                st_uid INTEGER NOT NULL, \
                st_gid INTEGER NOT NULL, \
                st_rdev INTEGER NOT NULL, \
                st_size INTEGER NOT NULL, \
                st_blksize INTEGER NOT NULL, \
                st_blocks INTEGER NOT NULL, \
                st_atime INTEGER NOT NULL, \
                st_mtime INTEGER NOT NULL, \
                st_ctime INTEGER NOT NULL, \
                archive TEXT, \
                archive_parent TEXT \
                );\
                ", tableName);
        
        char *zErrMsg = 0;
        int err;
        if((err = sqlite3_exec(db, buffer, NULL, NULL, &zErrMsg)) != SQLITE_OK){
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                // printf("Error: %d\n", err);
                sqlite3_free(zErrMsg);
                return err; 
        }
        printf("Table %s created successfully\n", tableName);


        return 0; 
}







