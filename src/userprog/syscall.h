#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Declare pid_t here to avoid error */
typedef int pid_t;

/* Juan Driving
* A global lock in to protect syscall functions, 
* idea given credit to Piazza post @704 */
struct lock file_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
