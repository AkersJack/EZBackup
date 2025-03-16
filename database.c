#include "database.h"
#include <stdlib.h>

/* 
        The table that gets created should have the same name as the file 
        that is written to disk. 
        

        The directory structure and the files saved within the archives is 
        what gets written to the actual table. (essentially stat command stuff)



*/


int addItem(sqlite3 *db, char *tableName, dbItem *item){
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
        // Here Test is the table name 
        // Add time into sql statement
        char sql[] = "INSERT INTO Test ("
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
                                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
        

        printf("Item->name: %s\n", item->name);
        printf("Item->path: %s\n", item->path);

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

int showTableItems(sqlite3 *db, char *tableName){
        char baseString[] = "SELECT * FROM "; 
        char *sql = malloc(strlen(baseString) + strlen(tableName) + 2);
        memcpy(sql, baseString, strlen(baseString));
        strncat(sql, tableName, strlen(tableName));
        sql[strlen(baseString) + strlen(tableName)] = ';';
        
        char *err_msg; 
        int rc; 
        
        rc = sqlite3_exec(db, sql, query_callback, NULL, &err_msg);
        if (rc != SQLITE_OK){
                fprintf(stderr, "SQL error: %s\n", err_msg);
                sqlite3_free(err_msg);
                free(sql);
                return 1; 
        }
        printf("%s\n", sql);

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



int createTable(sqlite3 *db, char* tableName){

        char buffer[1024];
        // time is the datetime of when that item was backed-up (last backup)
        /*
         * ADD
        * time DATETIME NOT NULL, 
        */
        snprintf(buffer, sizeof(buffer), 
                "CREATE TABLE %s (id INTEGER PRIMARY KEY AUTOINCREMENT, \
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
                st_ctime INTEGER NOT NULL \
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







