#include "tools.h"
#include "rsync.h"
#include "database.h"
#include "config.h"


/*
 * For local transfer using rsync: 
 * 1. use rsync to generate file list 
 * 2. pipe file list into tar 
 * 3. compress and encrypt
*/