#include <stdio.h>
#include <sys/ioctl.h> // Get terminal width 
#include <stdlib.h> // For system commands (like clearing the screen)
#include <ncurses.h>
#include <string.h>
                    

/*
   █████████████████████████████████████████████
   █                 EZBackup                  █
   █████████████████████████████████████████████


   ncurses (ncurses library) // maybe use for cli changes
                             // It is used to created character-based interfaces
                             // (TUIs) in a terminal-independent way

   Notcurses (more modern form of incurses)
   PDCurses (portability across multiple platforms)
   Turbo Vision (A modern cross-platform port of classic Borland Turbo vision framework)



   

   Call rsync and dd using fork() 
   

   using pipe() to create a pipe and capture stdout. 
   Should also create a pipe() to capture stderr

   dup2()
   

   rsync: https://linux.die.net/man/1/rsync
   rsync config file (rsync.confd): https://linux.die.net/man/5/rsyncd.conf
                                        
   Don't need to use rsync daemon when doing rsync over an ssh connection
   
   use rsync over ssh for an encrypted connection 
   
   
   If user selects rsync() before transfer transmit to server what is happening (for logs)
    - Also update the transfer DB 


*/

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define MAX_MENU_ITEMS 100
#define MENU_WIDTH 200

#define MENU_TITLE "EzBackup" // Define the menu title

int rsyncMenu(){
        char *choices[] = {
            "-v, --verbose               increase verbosity",
            "-q, --quiet                 suppress non-error messages",
            "-c, --checksum              skip based on checksum, not mod-time & size",
            "-a, --archive               archive mode; equals -rlptgoD (no -H,-A,-X)",
            "    --no-OPTION             turn off an implied OPTION (e.g. --no-D)",
            "-r, --recursive             recurse into directories",
            "-R, --relative              use relative path names",
            "    --no-implied-dirs       don't send implied dirs with --relative",
            "-b, --backup                make backups (see --suffix & --backup-dir)",
            "    --backup-dir=DIR        make backups into hierarchy based in DIR",
            "    --suffix=SUFFIX         backup suffix (default ~ w/o --backup-dir)",
            "-u, --update                skip files that are newer on the receiver",
            "    --inplace               update destination files in-place",
            "    --append                append data onto shorter files",
            "    --append-verify         --append w/old data in file checksum",
            "-d, --dirs                  transfer directories without recursing",
            "-l, --links                 copy symlinks as symlinks",
            "-L, --copy-links            transform symlink into referent file/dir",
            "    --copy-unsafe-links     only \"unsafe\" symlinks are transformed",
            "    --safe-links            ignore symlinks that point outside the tree",
            "-k, --copy-dirlinks         transform symlink to dir into referent dir",
            "-K, --keep-dirlinks         treat symlinked dir on receiver as dir",
            "-H, --hard-links            preserve hard links",
            "-p, --perms                 preserve permissions",
            "-E, --executability         preserve executability",
            "    --chmod=CHMOD           affect file and/or directory permissions",
            "-A, --acls                  preserve ACLs (implies -p)",
            "-X, --xattrs                preserve extended attributes",
            "-o, --owner                 preserve owner (super-user only)",
            "-g, --group                 preserve group",
            "    --devices               preserve device files (super-user only)",
            "    --specials              preserve special files",
            "-D                          same as --devices --specials",
            "-t, --times                 preserve modification times",
            "-O, --omit-dir-times        omit directories from --times",
            "    --super                 receiver attempts super-user activities",
            "    --fake-super            store/recover privileged attrs using xattrs",
            "-S, --sparse                handle sparse files efficiently",
            "-n, --dry-run               perform a trial run with no changes made",
            "-W, --whole-file            copy files whole (w/o delta-xfer algorithm)",
            "-x, --one-file-system       don\'t cross filesystem boundaries",
            "-B, --block-size=SIZE       force a fixed checksum block-size",
            "-e, --rsh=COMMAND           specify the remote shell to use",
            "    --rsync-path=PROGRAM    specify the rsync to run on remote machine",
            "    --existing              skip creating new files on receiver",
            "    --ignore-existing       skip updating files that exist on receiver",
            "    --remove-source-files   sender removes synchronized files (non-dir)",
            "    --del                   an alias for --delete-during",
            "    --delete                delete extraneous files from dest dirs",
            "    --delete-before         receiver deletes before transfer (default)",
            "    --delete-during         receiver deletes during xfer, not before",
            "    --delete-delay          find deletions during, delete after",
            "    --delete-after          receiver deletes after transfer, not before",
            "    --delete-excluded       also delete excluded files from dest dirs",
            "    --ignore-errors         delete even if there are I/O errors",
            "    --force                 force deletion of dirs even if not empty",
            "    --max-delete=NUM        don\'t delete more than NUM files",
            "    --max-size=SIZE         don\'t transfer any file larger than SIZE",
            "    --min-size=SIZE         don\'t transfer any file smaller than SIZE",
            "    --partial               keep partially transferred files",
            "    --partial-dir=DIR       put a partially transferred file into DIR",
            "    --delay-updates         put all updated files into place at end",
            "-m, --prune-empty-dirs      prune empty directory chains from file-list",
            "    --numeric-ids           don\'t map uid/gid values by user/group name",
            "    --timeout=SECONDS       set I/O timeout in seconds",
            "    --contimeout=SECONDS    set daemon connection timeout in seconds",
            "-I, --ignore-times          don't skip files that match size and time",
            "    --size-only             skip files that match in size",
            "    --modify-window=NUM     compare mod-times with reduced accuracy",
            "-T, --temp-dir=DIR          create temporary files in directory DIR",
            "-y, --fuzzy                 find similar file for basis if no dest file",
            "    --compare-dest=DIR      also compare received files relative to DIR",
            "    --copy-dest=DIR         ... and include copies of unchanged files",
            "    --link-dest=DIR         hardlink to files in DIR when unchanged",
            "-z, --compress              compress file data during the transfer",
            "    --compress-level=NUM    explicitly set compression level",
            "    --skip-compress=LIST    skip compressing files with suffix in LIST",
            "-C, --cvs-exclude           auto-ignore files in the same way CVS does",
            "-f, --filter=RULE           add a file-filtering RULE",
            "-F                          same as --filter=\'dir-merge /.rsync-filter\'",
            "                            repeated: --filter=\'- .rsync-filter\'",
            "    --exclude=PATTERN       exclude files matching PATTERN",
            "    --exclude-from=FILE     read exclude patterns from FILE",
            "    --include=PATTERN       don't exclude files matching PATTERN",
            "    --include-from=FILE     read include patterns from FILE",
            "    --files-from=FILE       read list of source-file names from FILE",
            "-0, --from0                 all *from/filter files are delimited by 0s",
            "-s, --protect-args          no space-splitting; wildcard chars only",
            "    --address=ADDRESS       bind address for outgoing socket to daemon",
            "    --port=PORT             specify double-colon alternate port number",
            "    --sockopts=OPTIONS      specify custom TCP options",
            "    --blocking-io           use blocking I/O for the remote shell",
            "    --stats                 give some file-transfer stats",
            "-8, --8-bit-output          leave high-bit chars unescaped in output",
            "-h, --human-readable        output numbers in a human-readable format",
            "    --progress              show progress during transfer",
            "-P                          same as --partial --progress",
            "-i, --itemize-changes       output a change-summary for all updates",
            "    --out-format=FORMAT     output updates using the specified FORMAT",
            "    --log-file=FILE         log what we're doing to the specified FILE",
            "    --log-file-format=FMT   log updates using the specified FMT",
            "    --password-file=FILE    read daemon-access password from FILE",
            "    --list-only             list the files instead of copying them",
            "    --bwlimit=KBPS          limit I/O bandwidth; KBytes per second",
            "    --write-batch=FILE      write a batched update to FILE",
            "    --only-write-batch=FILE like --write-batch but w/o updating dest",
            "    --read-batch=FILE       read a batched update from FILE",
            "    --protocol=NUM          force an older protocol version to be used",
            "    --iconv=CONVERT_SPEC    request charset conversion of filenames",
            "    --checksum-seed=NUM     set block/file checksum seed (advanced)",
            "-4, --ipv4                  prefer IPv4",
            "-6, --ipv6                  prefer IPv6",
            "Exit",
        };
}

/* I should redo this */
int toolMenu(){
        
        WINDOW *menu_win;
        int highlight = 0;
        int choice = -1;
        int c;
    
        char *choices[] = {
            "rsync",
            "dd",
            "partclone",
            "CloneZilla",
            "ezBackup",
            "Exit",
        };
    
        int n_choices = ARRAY_SIZE(choices);
        int startx, starty, width;
        int title_len = strlen(MENU_TITLE);
        int title_start_x;
        int box_starty;
    
        initscr();             /* Start curses mode */
        clear();               /* Clear the screen */
        noecho();              /* Don't echo user input */
        cbreak();              /* Disable line buffering */
        keypad(stdscr, TRUE); /* Enable special keys (like arrow keys) */
        curs_set(0);           /* Hide the cursor */
    
        /* Calculate the starting position for the menu box */
        width = MENU_WIDTH;
        box_starty = (LINES - n_choices - 2) / 2 + 2; // Shift down to leave space for the title and a gap
        startx = (COLS - width) / 2;
    
        /* Calculate the starting position for the title (above the box) */
        title_start_x = (COLS - title_len) / 2;
        starty = box_starty - 2; // Position the title two lines above the box
    
        /* Print the title on the standard screen */
        mvprintw(starty, title_start_x, "%s", MENU_TITLE);
        refresh(); // Important: Refresh the standard screen
    
        /* Create a new window for the menu */
        menu_win = newwin(n_choices + 2, width, box_starty, startx);
        box(menu_win, 0, 0); /* Draw a border around the menu */
        keypad(menu_win, TRUE);
    
        /* Print the menu items */
        for (int i = 0; i < n_choices; ++i) {
            if (i == highlight) {
                wattron(menu_win, A_REVERSE); /* Highlight the current choice */
                mvwprintw(menu_win, i + 1, 1, "%s", choices[i]);
                wattroff(menu_win, A_REVERSE);
            } else {
                mvwprintw(menu_win, i + 1, 1, "%s", choices[i]);
            }
        }
        wrefresh(menu_win); /* Refresh the menu window */
    

        while (choice == -1) {
            c = wgetch(menu_win);
            switch (c) {
                case KEY_UP:
                    if (highlight > 0) {
                        highlight--;
                    }
                    break;
                case KEY_DOWN:
                    if (highlight < n_choices - 1) {
                        highlight++;
                    }
                    break;
                case 10: /* Enter key */
                    choice = highlight;
                    mvprintw(LINES - 2, 0, "You chose: %s\n", choices[choice]);
                    refresh();
                //     getch(); /* Wait for user input before exiting */
                    if(choice != 5){
                            choice = -1; 
                    }
                    break;
            }
    
            /* Redraw the menu with the updated highlight */
            for (int i = 0; i < n_choices; ++i) {
                if (i == highlight) {
                    wattron(menu_win, A_REVERSE);
                    mvwprintw(menu_win, i + 1, 1, "%s", choices[i]);
                    wattroff(menu_win, A_REVERSE);
                } else {
                    mvwprintw(menu_win, i + 1, 1, "%s", choices[i]);
                }
            }
            wrefresh(menu_win);
        }
    
        /* Handle the menu choice */
        mvprintw(LINES - 2, 0, "You chose: %s\n", choices[choice]);
        refresh();
        getch(); /* Wait for user input before exiting */
    
        endwin(); /* End curses mode */
    
        if (choice == n_choices - 1) {
            printf("Exiting...\n");
        } else {
            printf("You selected option %d: %s\n", choice + 1, choices[choice]);
        }
        
    return 0; 

}

int main(int argc, char *argv[]){
        // Emoji
        // printf("\U0001f984\n");
        // 
        // for(int i = 0; i < 20; i++){
        //         /* Full block char in UTF-8 */
        //         printf("\xE2\x96\x88");
        // }
        toolMenu();
        return 0;
}