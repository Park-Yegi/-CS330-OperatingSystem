#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct lock filesys_lock;

void syscall_init (void);
void check_userptr (const char *ptr);
void check_userptr_pf (const char *ptr);
void exit(int status);
struct fd_elem *fd_list_iter (struct list *fd_list, int fd);

#endif /* userprog/syscall.h */
