#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);
static int temp_sector = 1;

#define FD_START 2
#define FD_END 127

/* Initialize global lock */
void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&file_lock);
}

/* Keegan Driving
 * Verifies if the pointer passed in is a valid pointer, a valid
 * pointer is one that is not null, pointing to kernel virtual
 * address, and if the pointer is not mapped to a user address */
static bool
verify_pointer (const void *pointer)
{
    struct thread *cur = thread_current ();
    
    if (pointer == NULL || is_kernel_vaddr (pointer)
        || pagedir_get_page (cur->pagedir, pointer) == NULL) {
        return false;
    }
    
    return true;
}

/* Juan Driving
 * Look for the file with file descriptor fd in the thread's
 * list of open files */
// static struct open_file *
// get_file (int fd)
// {
//   struct thread *cur = thread_current ();

//   /* Iterating list element for file struct and last file list element */
//   struct list_elem *iterate = list_begin(&cur->file_list);
//   struct list_elem *end = list_end(&cur->file_list);

//   /* Traverse through thread's list of file */
//   while(iterate != end) {
//     /* Grab file struct and check its file descriptor */
//     struct open_file *cur_file =
//                       list_entry (iterate, struct open_file, file_elem);
//     if(cur_file->fd == fd) {
//       return cur_file;
//     }
//     iterate = list_next (iterate);
//   }
//   return NULL;
// }

/* Return the last inode from the line path */
static struct inode *
furthest_inode(char *line, char *recent)
{
    char *save_ptr, *token;
    struct dir *cur_dir, *next_dir = NULL;
    struct inode *inode, *temp;
    
    /* Get the sector of the running directory */
    int sector = line[0] == '/' ? 1 :
    thread_current ()->directory;
    
    /* Get a copy for the current direcotry */
    char *dir_copy = palloc_get_page(0);
    if (!dir_copy) {
        return TID_ERROR;
    }
    
    /* Get the paths in the current directory */
    strlcpy(dir_copy, line, PGSIZE);
    token = strtok_r(dir_copy, "/", &save_ptr);
    
    /* Iterate all paths */
    while (token) {
        
        /* Copy over path and get sector */
        strlcpy(recent, token, strlen(token) + 1);
        sector = !strcmp(token, "..") ? temp->data.parent_dir : sector;
        
        /* Assign an inode and direcotry associated with sector */
        temp = inode_open(sector);
        cur_dir = dir_open(temp);
        
        /* If a directory with a token name exists and the inode is a directory,
         * then move on to the next directory */
        if(dir_lookup(cur_dir, token, &inode) && inode->data.is_directory) {
            next_dir = dir_open(inode);
            sector = next_dir->inode->sector;
            
            cur_dir = next_dir;
        }
        token = strtok_r(NULL, "/", &save_ptr);
    }
    
    temp_sector = sector;
    palloc_free_page(dir_copy);
    return inode;
}

/* Juan Driving */
static void
user_halt ()
{
    shutdown_power_off ();
}

/* Terminate the user program currently running and save the exit
 * status into the current user program for a waiting parent */
static void
user_exit (int status)
{
    thread_current ()->exit_status = status;
    thread_exit ();
}

/* Keegan Driving
 * Runs the executable whose name is given in cmd_line, passing
 * any given arguments, and returns the new process's program id */
static pid_t
user_exec (const char *cmd_line)
{
    if (!verify_pointer (cmd_line)) {
        user_exit (-1);
    }
    return process_execute (cmd_line);
}

/* Wait on a child process to terminate and collect its exit status */
static int
user_wait (pid_t pid)
{
    return process_wait (pid);
}

/* Create a new file with initial_size bytes in size and return true
 * if successful, false otherwise */
static bool
user_create (const char *file, unsigned initial_size)
{
    lock_acquire (&file_lock);
    
    bool success;
    struct dir *dir;
    struct inode *inode, *temp;
    char name[15];
    int sector = -1;
    
    if(!verify_pointer(file)) {
        lock_release (&file_lock);
        user_exit (-1);
    }
    
    /* Make sure the file name is acceptable */
    if (strlen(file) > 14 || strlen(file) < 1) {
        lock_release (&file_lock);
        return false;
    }
    
    /* Use the temporary inode to be the thread's directory and
     * exit function if inode was deleted */
    temp = inode_open(thread_current ()->directory);
    if (file[0] != '/' && temp->removed) {
        lock_release (&file_lock);
        return false;
    }
    
    /* Get directory of the inode and the last inode of the file */
    dir = dir_open(temp);
    inode = furthest_inode(file, name);
    
    /* If the inode is not NULL, then return false because you need
     * to have space to create */
    if (inode) {
        dir_close(dir);
        lock_release (&file_lock);
        return false;
    }
    dir_close(dir);
    
    /* Since we can create an inode, we do so and exit if failed */
    free_map_allocate(1, &sector);
    if(!inode_create(sector, initial_size, 0)) {
        lock_release (&file_lock);
        return false;
    }
    
    /* Successful in creating an inode, so we get sector of furthest inode
     * open that directory */
    temp = inode_open(temp_sector);
    dir = dir_open(temp);
    
    /* We add the directory to the sector */
    success = dir_add(dir, name, sector);
    
    /* Add the sector to the parent directory */
    inode = inode_open(sector);
    inode->data.parent_dir = dir->inode->sector;
    
    inode_close(inode);
    dir_close(dir);
    
    lock_release (&file_lock);
    return success;
}

/* Deletes file */
static bool
user_remove (const char *file)
{
    lock_acquire (&file_lock);
    
    struct dir *dir;
    struct inode *inode, *temp;
    char name[15], temp_fn[15];
    
    if(!verify_pointer(file)) {
        lock_release (&file_lock);
        user_exit (-1);
    }
    
    /* Return false if the file is a path, current directory, or parent */
    if (!strcmp(file, "/") || !strcmp(file, ".") || !strcmp(file, "..")) {
        lock_release (&file_lock);
        return false;
        
        /* Able to remove file */
    } else {
        /* Look for most recent inode, return false if not found, already
         * removed, or sector is not removable */
        inode = furthest_inode(file, name);
        if (!inode || inode->removed || inode->sector == 1) {
            lock_release (&file_lock);
            return false;
        }
        
        /* If inode is a directory */
        if (inode->data.is_directory) {
            dir = dir_open(inode);
            
            /* Return false if directory had no more entries */
            if (dir_readdir(dir, temp_fn)) {
                
                dir_close(dir);
                lock_release (&file_lock);
                return false;
            }
        }
        
        /* Either inode was not a directory or had more entries, so
         * remove directory with name and remove the inode */
        temp = inode_open(inode->data.parent_dir);
        dir = dir_open(temp);
        dir_remove(dir, name);
        dir_close(dir);
        inode_remove(inode);
    }
    
    lock_release (&file_lock);
    return true;
}

/* Juan Driving
 * Opens file file and returns the file descriptor */
static int
user_open (const char *file)
{
    lock_acquire (&file_lock);
    
    struct thread *cur = thread_current();
    struct file *cur_file;
    struct dir *dir;
    struct inode *inode, *temp;
    int fd = 2;
    bool success = false;
    char name[15], temp_fn[15];
    
    if(!verify_pointer(file)) {
        lock_release (&file_lock);
        user_exit (-1);
    }
    
    /* Return -1 if unable to hold more files */
    if(cur->file_list_array[FD_END] || !strlen(file)) {
        lock_release (&file_lock);
        return -1;
    }
    
    /* If file is a path, then open the first file after */
    if (!strcmp(file, "/")) {
        inode = inode_open(1);
        cur_file = file_open(inode);
        
        /* If we are in the current directory, then get file from thread */
    } else if (!strcmp(file, ".")) {
        inode = inode_open(cur->directory);
        if (inode->removed) {
            lock_release (&file_lock);
            return -1;
        }
        cur_file = file_open(inode);
        
        /* If we are in the parent directory, then go to parent directory
         * and get file there */
    } else if (!strcmp(file, "..")) {
        inode = inode_open(cur->directory);
        
        /* Exit if the inode has been deleted */
        if (inode->removed) {
            inode_close(inode);
            lock_release (&file_lock);
            return -1;
        }
        
        /* Use the inode to get the parent directory */
        temp = inode_open(inode->data.parent_dir);
        inode_close(inode);
        
        /* If parent inode is deleted, then exit */
        if (temp->removed) {
            inode_close(temp);
            lock_release (&file_lock);
            return -1;
        }
        cur_file = file_open(temp);
        
        /* Open the current directory and look for the most
         * recent inode */
    } else {
        
        /* Get the furthest inode */
        temp = inode_open(cur->directory);
        dir = dir_open(temp);
        inode = furthest_inode(file, name);
        dir_close(dir);
        
        /* If the inode was not found or has been removed,
         * then exit method */
        if (!inode || inode->removed) {
            lock_release (&file_lock);
            return -1;
        }
        cur_file = file_open(inode);
    }
    
    /* Exit if the file was null */
    if (!cur_file) {
        lock_release (&file_lock);
        return -1;
    }
    
    /* Update directory status for file and if it is a directory,
     * then update the directory pointer for the file */
    cur_file->is_directory = inode->data.is_directory;
    if (inode->data.is_directory) {
        cur_file->directory_ptr = dir_open(cur_file->inode);
    }
    
    /* Find a spot for the new file in the threads array of files */
    while (cur->file_list_array[fd] && fd < 128) {
        fd++;
    }
    cur->file_list_array[fd] = cur_file;
    
    lock_release (&file_lock);
    return fd;
}

/* Return length in number of bytes for file fd */
static int
user_filesize (int fd)
{
    lock_acquire (&file_lock);
    
    if (!(fd >= FD_START && fd <= FD_END)) {
        lock_release (&file_lock);
        return -1;
    }
    struct file *cur_file = thread_current ()->file_list_array[fd];
    
    lock_release (&file_lock);
    return cur_file->inode->data.length;
}

/* Keegan Driving
 * Read a size number of bytes from the file with fd as the
 * file descriptor and save what has been read into buffer */
static int
user_read (int fd, void *buffer, unsigned size)
{
    if (!verify_pointer(buffer)) {
        user_exit (-1);
    }
    
    struct thread *cur = thread_current();
    struct file *cur_file = NULL;
    int bytes_read = 0;
    
    /* Make sure file_descriptor is appropriate */
    if(!(fd >= FD_START && fd <= FD_END) || !(cur->file_list_array[fd])) {
        return -1;
    }
    
    cur_file = cur->file_list_array[fd];
    
    /* Get the file with fd and read the bytes */
    if(fd) {
        lock_acquire (&file_lock);
        bytes_read = file_read (cur_file, buffer, size);
        lock_release (&file_lock);
        
        /* Otherwise if the file descriptor is 0 (is a standard input),
         * then get a key from input buffer */
    } else {
        while(size > 0) {
            input_getc();
            size--;
            bytes_read++;
        }
    }
    
    return bytes_read;
}

/* Juan Driving
 * Writes size bytes from buffer to the open file fd or to the console*/
static int
user_write (int fd, const void *buffer, unsigned size)
{
    if (!verify_pointer(buffer)) {
        user_exit (-1);
    }
    
    int bytes_written = 0;
    char *bufChar = (char *)buffer;
    struct file *cur_file = NULL;
    size_t few_hundred_bytes = 200;
    
    if (fd <= 0 || fd > FD_END || size < 0) {
        return -1;
    }
    
    /* Write to the console */
    if (fd == 1) {
        
        /* Break up larger buffers, write few_hundred_bytes in
         * console_buf to the console, and decrease size to account
         * for bytes already written */
        while(size > few_hundred_bytes) {
            putbuf(bufChar, few_hundred_bytes);
            bufChar += few_hundred_bytes;
            
            size -= few_hundred_bytes;
            bytes_written += few_hundred_bytes;
        }
        
        /* Once size is no longer than the buffer max,
         * call the putbuf once more */
        putbuf(bufChar, size);
        bytes_written += size;
        
        /* Write to the file with fd as its descriptor */
    } else {
        cur_file = thread_current ()->file_list_array[fd];
        
        /* If cur_file is NULL or the file is a directory, exit */
        if(!cur_file || cur_file->inode->data.is_directory) {
            return -1;
        }
        
        lock_acquire (&file_lock);
        bytes_written = file_write(cur_file, buffer, size);
        lock_release (&file_lock);
    }
    
    return bytes_written;
}

/* Keegan Driving
 * Changes the next byte to be read or written in open file fd to
 * position, expressed in bytes from the beginning of the file */
static void
user_seek (int fd, unsigned position)
{
    if (!(fd >= FD_START && fd <= FD_END)) {
        return;
    }
    
    struct file *cur_file = thread_current ()->file_list_array[fd];
    
    lock_acquire (&file_lock);
    file_seek(cur_file, position);
    lock_release (&file_lock);
}

/* Returns the position of the next byte to be read/written in open file fd */
static unsigned
user_tell (int fd)
{
    if (!(fd >= FD_START && fd <= FD_END)) {
        return;
    }
    
    unsigned position;
    struct file *cur_file = thread_current ()->file_list_array[fd];
    
    lock_acquire (&file_lock);
    position = file_tell(cur_file);
    lock_release (&file_lock);
    
    return position;
}

/* Closes the file fd and frees up allocated memory */
static void
user_close (int fd)
{
    if (!(fd >= FD_START && fd <= FD_END)) {
        return;
    }
    
    struct thread *cur = thread_current ();
    struct file *cur_file = cur->file_list_array[fd];
    
    if (!cur_file) {
        return;
    }
    
    lock_acquire (&file_lock);
    file_close (cur_file);
    lock_release (&file_lock);
    
    cur->file_list_array[fd] = NULL;
}

/* Keegan Driving */
/* Changes the current directory of the thread to dir */
static bool
user_chdir (const char *dir)
{
    struct thread *cur = thread_current ();
    struct dir *temp_dir;
    struct inode *inode, *temp;
    char name[15];
    bool success = true;
    
    /* If we are in a path, set the directory */
    if (!strcmp(dir, "/")) {
        cur->directory = 1;
        
        /* If dir is a parent, then get the parent's directory */
    } else if (!strcmp(dir, "..")) {
        inode = inode_open(cur->directory);
        cur->directory = inode->data.parent_dir;
        inode_close(inode);
        
        /* Otherwise, get the most recent inode and try to find the
         * directory through the inode's sector */
    } else {
        temp = inode_open(cur->directory);
        
        /* Find the furthest inode */
        temp_dir = dir_open(temp);
        inode = furthest_inode(dir, name);
        dir_close(temp_dir);
        
        /* If an inode is found, then get the secotr for the directory */
        success = inode && !(inode->removed);
        if (success) {
            cur->directory = inode->sector;
            inode_close(inode);
        }
    }
    return success;
}

/* Juan Driving */
/* Create a directory */
static bool
user_mkdir (const char *dir)
{
    struct dir *temp_dir;
    struct inode *inode, *temp;
    int new_sector = -1;
    char name[15];
    bool success = false;
    
    /* Get most recent inode and open it */
    inode = furthest_inode(dir, name);
    temp = inode_open(temp_sector);
    temp_dir = dir_open(temp);
    
    /* If no inode was found, create a directory */
    if (!inode) {
        free_map_allocate(1, &new_sector);
        
        /* If we are able to create a directory at sector 1, then
         * add directory to current dir */
        if(dir_create(new_sector, 16)) {
            success = dir_add(temp_dir, name, new_sector);
            
            /* Open inode and assign parent directory to inode */
            inode = inode_open(new_sector);
            inode->data.parent_dir = temp_dir->inode->sector;
            inode_close(inode);
            dir_close(temp_dir);
            
            /* If unsuccessful in creating directory, then de-allocate
             * disk sector */
            if(!success) {
                free_map_release(new_sector, 1);
            }
        }
    }
    return success;
}

/* Keegan Driving */
/* Read the directory entry with fd as its descriptor */
static bool
user_readdir (int fd, const char* name)
{
    struct file *cur_file = thread_current ()->file_list_array[fd];
    
    /* Can only read if file is a directory */
    return cur_file || cur_file->is_directory ?
    dir_readdir(cur_file->directory_ptr, name) : false;
}

/* Determin if the inode with fd as its descriptor is a directory */
static bool
user_isdir (int fd)
{
    /* Check bounds */
    if(!(fd >= FD_START && fd <= FD_END)) {
        user_exit (-1);
    }
    
    /* Return the inode's member for directory */
    struct file *cur_file = thread_current ()->file_list_array[fd];
    return cur_file ? cur_file->is_directory : false;
}

/* Juan Driving */
/* Returns the inode number with fd as its descriptor */
static int
user_inumber (int fd)
{
    /* Check bounds */
    if (!(fd >= FD_START && fd <= FD_END)) {
        user_exit (-1);
    }
    
    /* Return the disk location using the inode's sector member */
    struct file *cur_file = cur_file = thread_current ()->file_list_array[fd];
    return cur_file ? cur_file->inode->sector : -1;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    /* Keegan Driving
     * esp in the intr_frame will point to a number indicating the what
     * handler will be called */
    void *esp = f->esp;
    
    /* eax will be where we will store any output from system handlers to
     * act as the return value */
    uint32_t *eax = &f->eax;
    
    int *pointer = (int *) esp;
    if(!verify_pointer (pointer) || !verify_pointer (pointer + 1) ||
       !verify_pointer (pointer + 2)) {
        user_exit (-1);
    }
    
    bool within_bounds = pointer >= (f->esp - 32) && pointer <= (f->esp + 32);
    if(!within_bounds) {
        thread_exit ();
    }
    
    /* Juan Driving
     * Retrieve the system call number */
    int syscall_num = *((int *) esp);
    
    switch (syscall_num) {
        case SYS_HALT:
        {
            user_halt ();
            break;
        }
        case SYS_EXIT:
        {
            int status = *(((int *) esp) + 1);
            user_exit (status);
            break;
        }
        case SYS_EXEC:
        {
            const char *cmd_line = *(((char **) esp) + 1);
            *eax = (uint32_t) user_exec (cmd_line);
            break;
        }
        case SYS_WAIT:
        {
            pid_t pid = *(((pid_t *) esp) + 1);
            *eax = (uint32_t) user_wait (pid);
            break;
        }
        case SYS_CREATE:
        {
            const char *file = *(((char **) esp) + 1);
            unsigned initial_size = *(((unsigned *) esp) + 2);
            *eax = (uint32_t) user_create (file, initial_size);
            break;
        }
        case SYS_REMOVE:
        {
            const char *file = *(((char **) esp) + 1);
            *eax = (uint32_t) user_remove (file);
            break;
        }
        case SYS_OPEN:
        {
            const char *file = *(((char **) esp) + 1);
            *eax = (uint32_t) user_open (file);
            break;
        }
        case SYS_FILESIZE:
        {
            int fd = *(((int *) esp) + 1);
            *eax = (uint32_t) user_filesize (fd);
            break;
        }
        case SYS_READ:
        {
            int fd = *(((int *) esp) + 1);
            void *buffer = (void *) *(((int **) esp) + 2);
            unsigned size = *(((unsigned *) esp) + 3);
            *eax = (uint32_t) user_read (fd, buffer, size);
            break;
        }
        case SYS_WRITE:
        {
            int fd = *(((int *) esp) + 1);
            const void *buffer = (void *) *(((int **) esp) + 2);
            unsigned size = *(((unsigned *) esp) + 3);
            *eax = (uint32_t) user_write (fd, buffer, size);
            break;
        }
        case SYS_SEEK:
        {
            int fd = *(((int *) esp) + 1);
            unsigned position = *(((unsigned *) esp) + 2);
            user_seek (fd, position);
            break;
        }
        case SYS_TELL:
        {
            int fd = *(((int *) esp) + 1);
            *eax = (uint32_t) user_tell (fd);
            break;
        }
        case SYS_CLOSE:
        {
            int fd = *(((int *) esp) + 1);
            user_close (fd);
            break;
        }
        /* Juan Driving */
        case SYS_CHDIR:
        {
            const char* path = *(((char **) esp) + 1);
            *eax = (uint32_t) user_chdir (path);
            break;
        }
        case SYS_MKDIR:
        {
            const char* path = *(((char **) esp) + 1);
            *eax = (uint32_t) user_mkdir (path);
            break;
        }
        case SYS_READDIR:
        {
            int fd = *(((int *) esp) + 1);
            const char* name = *(((char **) esp) + 2);
            *eax = (uint32_t) user_readdir (fd, name);
            break;
        }
        case SYS_ISDIR:
        {
            int fd = *(((int *) esp) + 1);
            *eax = (uint32_t) user_isdir (fd);
            break;
        }
        case SYS_INUMBER:
        {
            int fd = *(((int *) esp) + 1);
            *eax = (uint32_t) user_inumber (fd);
            break;
        }
        default:
        {
            printf("Error: not a valid system call.");
            break;
        }
    }
}
