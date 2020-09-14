#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/off_t.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);
static void halt (void);
static void exit(int status);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static int allocate_fd(void);
static struct fd_elem *fd_list_iter (struct list *fd_list, int fd);

static struct lock filesys_lock;
static struct lock fd_lock;       /* lock for file descriptor open */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&fd_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int status, fd;
  pid_t pid, result_pid;
  const char *file;
  void *buffer;
  unsigned initial_size, size, position;
 
  check_userptr(f->esp);

  switch (*((int*)(f->esp))) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_userptr((f->esp)+4);
      status = *((int*)((f->esp)+4));
      exit(status);
      break;
    case SYS_EXEC:
      check_userptr((f->esp)+4);
      file = *((char**)((f->esp)+4));
      f->eax = exec(file);
      break;
    case SYS_WAIT:
      check_userptr((f->esp)+4);
      pid = *((pid_t*)((f->esp)+4));
      f->eax = wait(pid);
      break;
    case SYS_CREATE:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      file = *((char**)((f->esp)+4));
      initial_size = *((unsigned*)((f->esp)+8));
      f->eax = create(file, initial_size);
      break;
    case SYS_REMOVE:
      check_userptr((f->esp)+4);
      file = *((char**)((f->esp)+4));
      f->eax = remove(file);
      break;
    case SYS_OPEN:
      check_userptr((f->esp)+4);
      file = *((char**)((f->esp)+4));
      f->eax = open(file);
      break;
    case SYS_FILESIZE:
      check_userptr((f->esp)+4);
      fd = *((int*)((f->esp)+4));
      f->eax = filesize(fd);
      break;
    case SYS_READ:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      check_userptr((f->esp)+12);
      fd = *((int*)((f->esp)+4));
      buffer = *((void**)((f->esp)+8));
      size = *((unsigned*)((f->esp)+12));
      f->eax = read(fd, buffer, size);
      break;
    case SYS_WRITE:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      check_userptr((f->esp)+12);
      fd = *((int*)((f->esp)+4));
      buffer = *((void**)((f->esp)+8));
      size = *((unsigned*)((f->esp)+12));
      f->eax = write(fd, buffer, size);
      break;
    case SYS_SEEK:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      fd = *((int*)((f->esp)+4));
      position = *((unsigned*)((f->esp)+8));
      seek(fd, position);
      break;
    case SYS_TELL:
      check_userptr((f->esp)+4);
      fd = *((int*)((f->esp)+4));
      f->eax = tell(fd);
      break;
    case SYS_CLOSE:
      check_userptr((f->esp)+4);
      fd = *((int*)((f->esp)+4));
      close(fd);
      break;
  }
}


void check_userptr (const char *ptr) {
  if (ptr==NULL) {
    exit(-1);
  }
  if (!is_user_vaddr(ptr) || (pagedir_get_page(thread_current()->pagedir, ptr)==NULL)) {
    exit(-1);
  }
}


static void halt (void) {
  power_off();
}

static void exit(int status) {
  char *save_ptr;
  struct list_elem *e, *e_next;
  struct child_info *temp;
  int exit_code;
  struct thread *alive_child;
  struct fd_elem *open_file;

  intr_disable();
  exit_code = status;
  
  printf ("%s: exit(%d)\n", strtok_r(thread_current()->name, " ", &save_ptr), exit_code);
  thread_current()->exit_status = status;


  /* Wait for child when parent exits */
  if (!list_empty(&thread_current()->children_thread_list)) {
    for (e=list_begin(&thread_current()->children_thread_list);
          e!=list_end(&thread_current()->children_thread_list);
          e=list_next(e)) {
            alive_child = list_entry(e, struct thread, elem_child);
            wait((pid_t)alive_child->tid);
          }
  }
  /*******************************************/

  /* Find me in my parent's child_info_list and change exit_status and exited */
  if (!list_empty(&thread_current()->parent_thread->child_info_list)) {
    for (e=list_begin(&thread_current()->parent_thread->child_info_list);
          e!=list_end(&thread_current()->parent_thread->child_info_list);
          e=list_next(e)) {
            temp = list_entry(e, struct child_info, elem);
            if (temp->tid == thread_current()->tid) {
              temp->exit_status = status;
              temp->exited = true;
            }
    }
  }
  /***************************************/

  /* Close all open file */
  if (!list_empty(&thread_current()->fd_list)) {
    for (e=list_begin(&thread_current()->fd_list);
          e!=list_end(&thread_current()->fd_list);
          e=list_next(e)) {
            open_file = list_entry(e, struct fd_elem, elem);
              lock_acquire(&filesys_lock);
              file_close(open_file->file_ptr);
              lock_release(&filesys_lock);
          }
  }
  /***********************/

  thread_exit();
}

static pid_t exec(const char *cmd_line) {
  tid_t tid;
  pid_t pid;
  struct list_elem *e;
  struct thread *child, *temp;

  check_userptr(cmd_line);

  lock_acquire(&filesys_lock);
  tid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  pid = (pid_t)tid;
  
  /***** Code for not to return exec before child's load is finished */
  if (!list_empty(&thread_current()->children_thread_list)) {
    for (e=list_begin(&thread_current()->children_thread_list); e != list_end(&thread_current()->children_thread_list); e=list_next(e)) {
      temp = list_entry(e, struct thread, elem_child);
      if (temp->tid == tid) {
        child = temp;
        break;
      }
    }
    sema_down(&child->parent_child_sync);
  }
  /*******************************************************************/

  return pid;
}

static int wait(pid_t pid) {
  int exit_status;
  exit_status = process_wait((tid_t)pid);
  return exit_status;
}

static bool create(const char *file, unsigned initial_size) {
  bool result;
  check_userptr(file);
  if (strlen(file) > 14) {
    return false;
  }

  lock_acquire(&filesys_lock);
  if (filesys_open(file) == NULL) {
    result = filesys_create(file, (off_t)initial_size);
  } else {
    lock_release(&filesys_lock);
    return false;
  }
  lock_release(&filesys_lock);
  return result;
}

static bool remove(const char *file) {
  bool result;
  check_userptr(file);

  lock_acquire(&filesys_lock);
  result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}

static int open(const char *file) {
  int fd;
  struct fd_elem *new_fd_elem;
  void *file_ptr;

  check_userptr(file);

  lock_acquire(&filesys_lock);
  file_ptr = filesys_open(file);

  if (file_ptr != NULL) {
    fd = allocate_fd();
    new_fd_elem = malloc(sizeof(struct fd_elem));
    new_fd_elem->fd = fd;
    new_fd_elem->file_ptr = file_ptr;
    list_push_back(&thread_current()->fd_list, &new_fd_elem->elem);
    lock_release(&filesys_lock);
    return fd;
  }
  else {
    lock_release(&filesys_lock);
    return -1;
  }
}

static int filesize(int fd) {
  struct fd_elem *temp;
  int size;

  temp = fd_list_iter(&thread_current()->fd_list, fd);

  if (temp != NULL) {
    lock_acquire(&filesys_lock);
    size = (int)file_length(temp->file_ptr);
    lock_release(&filesys_lock);
    return size;
  }
  else {
    return 0;
  }
}

static int read(int fd, void *buffer, unsigned size) {
  check_userptr(buffer);
  lock_acquire(&filesys_lock);

  struct fd_elem *temp;
  temp = NULL;
  int result;

  if (fd == 0) {
    input_getc();
    lock_release(&filesys_lock);
    return 1;
  }
  else {
    temp = fd_list_iter(&thread_current()->fd_list, fd);

    if (temp == NULL) {
      lock_release(&filesys_lock);
      return -1;
    }

    result = (int)file_read(temp->file_ptr, buffer, (off_t)size);
    lock_release(&filesys_lock);
    return result;
  }
}

static int write(int fd, void *buffer, unsigned size) {
  check_userptr(buffer);
  lock_acquire(&filesys_lock);

  struct fd_elem *temp;
  temp = NULL;
  int result;
  int file_size;
  
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  else {
    temp = fd_list_iter(&thread_current()->fd_list, fd);

    if (temp == NULL) {
      lock_release(&filesys_lock);
      return -1;
    }
    
    lock_release(&filesys_lock);
    file_size = filesize(fd);
    lock_acquire(&filesys_lock);
    if (file_size >= size) {
      result = (int)file_write(temp->file_ptr, buffer, (off_t)size);
    }
    else {
      result = (int)file_write(temp->file_ptr, buffer, (off_t)file_size);
    }
    lock_release(&filesys_lock);
    return result;
  }
}

static void seek(int fd, unsigned position) {
  struct fd_elem *temp;

  temp = fd_list_iter(&thread_current()->fd_list, fd);

  if (temp != NULL) {
    lock_acquire(&filesys_lock);
    file_seek(temp->file_ptr, (off_t)position);
    lock_release(&filesys_lock);
  }
  return ;
}

static unsigned tell(int fd) {
  off_t position;
  struct fd_elem *temp;

  temp = fd_list_iter(&thread_current()->fd_list, fd);

  if (temp != NULL) {
    lock_acquire(&filesys_lock);
    position = file_tell(temp->file_ptr);
    lock_release(&filesys_lock);
    return position;
  }

  return 0;
}

static void close(int fd) {
  struct fd_elem *temp;
  lock_acquire(&filesys_lock);

  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);
  
  if (temp != NULL) {
    file_close(temp->file_ptr);
    list_remove(&temp->elem);
    free(temp);
  }
  
  lock_release(&filesys_lock);
}

static int allocate_fd(void) {
  static int next_fd = 2;
  int fd;

  lock_acquire(&fd_lock);
  fd = next_fd++;
  lock_release(&fd_lock);

  return fd;
}


static struct fd_elem *fd_list_iter (struct list *fd_list, int fd) {
  struct fd_elem *temp;
  struct list_elem *e;

  if (!list_empty(fd_list)) {
    for (e=list_begin(fd_list); e!=list_end(fd_list); e=list_next(e)) {
      temp = list_entry(e, struct fd_elem, elem);
      if (temp -> fd == fd) {
        return temp;
      }
    }
  }
  return NULL;
}
