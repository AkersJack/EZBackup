#ifndef DATABASE_H
#define DATABASE_H

#include <sys/stat.h> 
#include <stdio.h>
#include <string.h> 
#include <sqlite3.h>
#include <time.h>

typedef struct{
        char *path; // Full path to file 
        struct stat *s; // Pointer to stat structure
        char *name; // Item name 

}dbItem;


/* 
        Each table in the Database needs to have a unique ID (table name) associated with it
        A table is a backup instance (a select group of items that have been backed up to the server)
                - The table shows which items have been backed up and the file info for those items. 
        

        There is a main database file that will manage these tables

        When a new backup is started the main db looks at what is being backed up. 
                - If this is a unique backup with no files being backed up in another backup instance 
                then a new table should be created for that backup 

                - If there are files that have already been backed-up in another backup instance 
                prompt the user with a few options: 
                        1. Ignore repeat items that exist in other backups 
                        2. Backup all files (allow for duplicate backups for files)
                        3. Backup and link (Continue with backup but create links with other backups)
                                - Essentially don't backup those items just use a foreign key 
                                to reference which backup those files are already stored in. 
                        
        



*/

/*
 * When you query the database each item is going to be 
   contained in this struct 
   
   (might not be the best way but it will be easy to deal with)
*/
typedef struct{
        int id; // ID of item in table 
        char *name; 
        char *path; 
        char *created; 
        long long st_dev; 
        long long st_ino; 
        long long st_mode;
        long long st_nlink; 
        long long st_uid;
        long long st_gid;
        long long st_rdev; 
        long long st_size;
        long long st_blksize; 
        long long st_blocks;
        long long st_Atime;
        long long st_Mtime; 
        long long st_Ctime; 
}dbObj;



struct dbObjNode{
        int size; // Number of items
        dbObj *item; // Item from the database 
        struct dbObjNode *next;
};

/*
        Callback function for checkTableName
*/

static int table_callback(void *data, int argc, char **argv, char **azColName);

/* Check if the tablename is an actual table that exists in the database
 * Protects against sql injection 
 * 0 if table exists 1 if not exists
*/

int checkTableName(sqlite3 *db, char *tableName); 

/* remove the oldest item in the database which has that name and path */
int removeOldItem(sqlite3 *db, char *tableName, char *name, char *path);

/*
 * Add an item to the table
*/
int addItem(sqlite3 *db, char *tableName, dbItem *item);


/*
 * Create the parent table that manages backups as well as other tables
 * id, tableName, backupID 
 * 
*/
int createTableParent(sqlite3 *db); 

/* 
        Create a new table in the database
        
        db - A pointer to the sqlite3 database 
        tableName - The name of the table that you want to create
*/

int createTableData(sqlite3 *db, char* tableName);

/* 
        Inits the database
        - creates table if it doesn't exist and opens the file
        - If the table exists it just opens the file  
        - Takes in a pointer to sqlite3 object
        
        * returns 1 on error 0 on success
*/
int init_Database(sqlite3 **db, char *filename);

/*
        Callback function that will be executed for each row in the result
*/
static int query_callback(void *data, int argc, char **argv, char **azColName);

/*
        Callback function that will return a list of dbContainer objects
*/
static int query_callback_obj(void *data, int argc, char **argv, char **azColName);

/*
 * Callback function for getting a name 
*/
static int gtn_callback(void *data, int argc, char **argv, char **azColName);

int showTableItems(sqlite3 *db, char *tableName);

/*
 * Get items which have a certain name
 * Args: 
 *      - pointer to open sqlite3 db
 *      - name of the file  
 *      - Buffer to write a list of items to 
*/
int getItems_name(sqlite3 *db, char* name, char *buff);

/*
 * Get items which have a specific path 
 * Args: 
 *      - pointer to open sqlite3 db
 *      - Buffer to write a list of items to 
 *      - The name of the table
 *      - The file path from realpath()
*/

int getItems_path(sqlite3 *db, char *table_name, char* path, struct dbObjNode *node);


/*
 * Get items which have a specific path 
 * Args: 
 *      - pointer to open sqlite3 db
 *      - Buffer to write a list of items to 
 *      - The file path from realpath()
 *      - The name of the file 
 *
 * This should only return 1 item
*/
int getItems(sqlite3 *db, char *table_name, char *name, char *path, struct dbObjNode *node);


// Free items from the linked list
int freeNodes(struct dbObjNode *node);

/*
 * We are going to do an iterative approach for table names 
 * If we create a new table we are just going to do T1 T2 T3 ...
 * So we list all of the tables and then we just iterate 
*/

int getTableName(sqlite3 *db, char *tableName); 


time_t parseTime(const char *datetime);

#endif