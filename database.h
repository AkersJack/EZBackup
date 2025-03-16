#ifndef DATABASE_H
#define DATABASE_H

#include <sys/stat.h> 
#include <stdio.h>
#include <string.h> 
#include <sqlite3.h>

typedef struct{
        char *path; // Full path to file 
        struct stat *s; // Pointer to stat structure
        char *name; // Item name 

}dbItem;

/*
 * Add an item to the table
*/
int addItem(sqlite3 *db, char *tableName, dbItem *item);

/* 
        Create a new table in the database
        
        db - A pointer to the sqlite3 database 
        tableName - The name of the table that you want to create
*/

int createTable(sqlite3 *db, char* tableName);

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

int showTableItems(sqlite3 *db, char *tableName);


#endif