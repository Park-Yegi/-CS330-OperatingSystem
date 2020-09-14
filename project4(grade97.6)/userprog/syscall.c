#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "devices/input.h"
#include <string.h>
#include <hash.h>


static void syscall_handler (struct intr_frame *);
static void halt (void);
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
static mapid_t mmap (int fd, void *addr);
static void munmap (mapid_t mapping);
static bool chdir (const char *dir);
static bool mkdir (const char *dir);
static bool readdir (int fd, char *name);
static bool isdir (int fd);
static int inumber (int fd); 

static int allocate_fd(void);
static mapid_t allocate_mid(void);
static void lazy_file_map (void *vaddr, struct sup_page_table_entry *found_entry);

static struct lock fd_lock;       /* lock for file descriptor open */
static struct lock mid_lock;      /* lock for map id allocate */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&fd_lock);
  lock_init(&mid_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int status, fd;
  pid_t pid;
  const char *file, *dir;
  void *buffer, *addr;
  unsigned initial_size, size, position;
  mapid_t mapping;
 
  check_userptr(f->esp);

  /* Save user stack pointer */
  thread_current()->user_f_esp = f->esp;
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
    case SYS_MMAP:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      fd = *((int*)((f->esp)+4));
      addr = *((void**)((f->esp)+8));
      f->eax = mmap(fd, addr);
      break;
    case SYS_MUNMAP:
      check_userptr((f->esp)+4);
      mapping = *((mapid_t*)((f->esp)+4));;
      munmap(mapping);
      break;
    case SYS_CHDIR:
      check_userptr((f->esp)+4);
      dir = *((char**)((f->esp)+4));
      f->eax= chdir(dir);
      break;
    case SYS_MKDIR:
      check_userptr((f->esp)+4);
      dir = *((char**)((f->esp)+4));
      f->eax = mkdir(dir);
      break;
    case SYS_READDIR:
      check_userptr((f->esp)+4);
      check_userptr((f->esp)+8);
      fd = *((int*)((f->esp)+4));
      dir = *((char**)((f->esp)+8));
      f->eax = readdir(fd, dir);
      break;
    case SYS_ISDIR:
      check_userptr((f->esp)+4);
      fd = *((int*)((f->esp)+4));
      f->eax = isdir(fd);
      break;
    case SYS_INUMBER:
      check_userptr((f->esp)+4);
      fd = *((int*)((f->esp)+4));
      f->eax = inumber(fd);
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


void check_userptr_pf (const char *ptr) {
  if (ptr==NULL) {
    exit(-1);
  }
  if (!is_user_vaddr(ptr)) {
    exit(-1);
  }
}


static void halt (void) {
  power_off();
}

void exit(int status) {
  char *save_ptr;
  struct list_elem *e;
  struct child_info *temp;
  int exit_code;
  struct thread *alive_child;
  struct fd_elem *open_file;

  exit_code = status;
  
  printf ("%s: exit(%d)\n", strtok_r(thread_current()->name, " ", &save_ptr), exit_code);
  thread_current()->exit_status = status;


  /* Wait for child when parent exits */
  if (!list_empty(&thread_current()->children_thread_list)) {
    for (e=list_begin(&thread_current()->children_thread_list);
          e!=list_end(&thread_current()->children_thread_list);
          e=list_next(e)) {
            alive_child = list_entry(e, struct thread, elem_child);
            process_wait(alive_child->tid);
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

  /* unmap all mapped files */
  if (!list_empty(&thread_current()->fd_list)) {
    for (e=list_begin(&thread_current()->fd_list);
      e!=list_end(&thread_current()->fd_list);
      e=list_next(e)) {
        open_file = list_entry(e, struct fd_elem, elem);
        if (open_file -> mmapped == true) {
          munmap(open_file->mapid);
        }
    }
  }

  /* Close all open file */
  if (!list_empty(&thread_current()->fd_list)) {
    for (e=list_begin(&thread_current()->fd_list);
          e!=list_end(&thread_current()->fd_list);
          e=list_next(e)) {
            open_file = list_entry(e, struct fd_elem, elem);
            file_close(open_file->file_ptr);
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
  struct file *file_ptr;
  struct dir *dir_ptr;

  check_userptr_pf(file);

  if (*file == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  file_ptr = filesys_open(file);

  if (file_ptr != NULL) {
    fd = allocate_fd();
    new_fd_elem = malloc(sizeof(struct fd_elem));

    if (inode_get_isdir(file_get_inode(file_ptr))) {
      dir_ptr = dir_open(file_get_inode(file_ptr));
      new_fd_elem->dir_ptr = dir_ptr;
    }
    else {
      new_fd_elem->dir_ptr = NULL;
    }

    new_fd_elem->fd = fd;
    new_fd_elem->file_ptr = file_ptr;
    new_fd_elem->vaddr = NULL;
    new_fd_elem->mmapped = false;
    new_fd_elem->mapid = NULL;
    new_fd_elem->isdir = inode_get_isdir(file_get_inode(file_ptr));
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
  struct fd_elem *temp = NULL;
  int result;

  check_userptr_pf(buffer);

  if (fd == 0) {
    input_getc();
    return 1;
  }
  else {
    temp = fd_list_iter(&thread_current()->fd_list, fd);

    if (temp == NULL) {
      return -1;
    }

    lock_acquire(&filesys_lock);
    result = (int)file_read(temp->file_ptr, buffer, (off_t)size);
    lock_release(&filesys_lock);
    return result;
  }
}

static int write(int fd, void *buffer, unsigned size) {
  check_userptr(buffer);

  struct fd_elem *temp;
  temp = NULL;
  int result;
  int file_size;
  
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  else {
    temp = fd_list_iter(&thread_current()->fd_list, fd);

    if (temp == NULL) {
      return -1;
    }

    lock_acquire(&filesys_lock);
    file_size = (int)file_length(temp->file_ptr);

    if (temp->isdir)
      result = -1;
    else
      result = (int)file_write(temp->file_ptr, buffer, (off_t)size);
    
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
  struct sup_page_table_entry *spte;

  lock_acquire(&filesys_lock);

  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);
  
  if (temp != NULL) {
    spte = page_lookup(temp->vaddr);

    if ((spte != NULL) && (temp->mmapped && !spte->loaded))
      lazy_file_map(spte->user_vaddr, spte);

    file_close(temp->file_ptr);
    list_remove(&temp->elem);
    free(temp);
  }
  
  lock_release(&filesys_lock);
}

static mapid_t mmap (int fd, void *addr) {
  int file_len;
  off_t file_ofs = 0;
  struct fd_elem *temp;
  mapid_t mid;
  int i;
  
  if (fd == 0 || fd == 1)
    return -1;
  if ((int)addr % PGSIZE)
    return -1;
  if (addr == 0)
    return -1;

  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);
  if (temp == NULL) {
    return -1;
  }
  
  lock_acquire(&filesys_lock);
  file_len = file_length(temp->file_ptr);
  lock_release(&filesys_lock);
  
  if (file_len == 0)
    return -1;

  int page_cnt = file_len/PGSIZE;
  if (file_len % PGSIZE)
    page_cnt++;

  for (i=0; i<page_cnt; i++) {
    if (page_lookup(addr + i*PGSIZE) != NULL)
      return -1;
  }
  if (addr == PHYS_BASE - 4096) // Overlap initial stack
    return -1;

  mid = allocate_mid();
  temp->mmapped = true;
  temp->mapid = mid;
  temp->vaddr = addr;

  while (file_len > 0) 
  {
    size_t page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
    
    struct sup_page_table_entry *new_file_pg;
    new_file_pg = malloc(sizeof(struct sup_page_table_entry));
    new_file_pg -> user_vaddr = addr;
    new_file_pg -> load_executable = false;
    new_file_pg -> loaded = false; 
    new_file_pg -> swapped = false;
    new_file_pg -> writable = true;
    new_file_pg -> page_read_bytes = page_read_bytes;
    new_file_pg -> file_ofs = file_ofs;
    new_file_pg -> mmapped = true;
    new_file_pg -> mid = mid;
    new_file_pg -> fd = fd;
    new_file_pg -> file_ptr = temp->file_ptr;
    new_file_pg -> page_cnt = page_cnt;
    hash_insert(&thread_current()->sup_page_table, &new_file_pg->hash_elem);

    /* Advance */
    file_len -= page_read_bytes;
    addr += PGSIZE;
    file_ofs += page_read_bytes;
  }

  return mid;
}

static void munmap (mapid_t mapping) {
  struct sup_page_table_entry *spte = NULL;
  struct thread *t = thread_current();
  int iter, file_len;
  uint32_t *vaddr;
  off_t file_ofs;
  struct fd_elem *temp = NULL;
  struct list_elem *e, *e_next;
  struct frame_table_entry *fte;

  if (!list_empty(&thread_current()->fd_list)) {
    for (e=list_begin(&thread_current()->fd_list); e!=list_end(&thread_current()->fd_list); e=list_next(e)) {
      temp = list_entry(e, struct fd_elem, elem);
      if (temp->mmapped && (temp -> mapid == mapping))
        break;
      else
        temp = NULL;
    }
  }

  if (temp == NULL)
    return;
  spte = page_lookup(temp->vaddr);
  
  
  lock_acquire(&filesys_lock);

  file_len = file_length(spte->file_ptr);
  vaddr = spte->user_vaddr;
  file_ofs = spte->file_ofs;

  for (iter = 0; iter < spte->page_cnt; iter++) {
    size_t page_write_bytes = file_len < PGSIZE ? file_len : PGSIZE;
    if (spte->dirty)
      file_write_at(spte->file_ptr, vaddr, page_write_bytes, file_ofs);
    spte -> mid = NULL;

    pagedir_clear_page(t->pagedir, vaddr);

    file_len -= page_write_bytes;
    vaddr = (uint32_t *)((int)vaddr + 4096);
    file_ofs += page_write_bytes;
  }

  if (!list_empty(&frame_table)) {
    e=list_begin(&frame_table);
    while (e!=list_end(&frame_table)) {
      e_next = list_next(e);
      fte = list_entry(e, struct frame_table_entry, elem);
      if (fte->spte->mid == mapping) {
        list_remove(e);
        palloc_free_page(fte->frame);
        free(fte);
      }
      e = e_next;
    }
  }

  hash_delete (&thread_current()->sup_page_table, &spte->hash_elem);
  free(spte);

  temp->mmapped = false;
  
  lock_release(&filesys_lock);
  return;
}


static bool chdir (const char *dir) {
  struct inode *dir_inode;
  struct dir *new_dir;

  if (dir_lookup(thread_current()->curr_dir, dir, &dir_inode)) {
    new_dir = dir_open(dir_inode); 
    dir_close(thread_current()->curr_dir);
    thread_current()->curr_dir = new_dir;
    return true;
  }
  else {
    return false;
  }
}

static bool mkdir (const char *dir) {
  struct inode *dir_inode;
  disk_sector_t inode_sector = 0;
  char *path, *file_name;
  struct dir *old_dir;

  // If there is already the same directory name, then fail
  if (dir_lookup(thread_current()->curr_dir, dir, &dir_inode))
    return false;

  path = (char*)malloc(strlen(dir)+1);
  memset(path, 0, strlen(dir)+1);
  file_name = (char*)malloc(14);
  memset(file_name, 0, 14);
  parse_path (dir, path, file_name);

  // If there is no parent directory, tne fail
  if (!dir_lookup(thread_current()->curr_dir, path, &dir_inode)) {
    free(path);
    free(file_name);
    return false;
  }

  old_dir = thread_current()->curr_dir;
  thread_current()->curr_dir = dir_open(dir_inode);
  free_map_allocate (1, &inode_sector);
  dir_create (inode_sector, 1, file_name);
  if (inode_get_inumber(dir_get_inode(old_dir)) != inode_get_inumber(dir_get_inode(thread_current()->curr_dir)))
    dir_close(thread_current()->curr_dir);
  thread_current()->curr_dir = old_dir;

  free(path);
  free(file_name);

  return true;
}

static bool readdir (int fd, char *name) {
  struct dir *dir;
  struct fd_elem *temp;
  bool result = false;
  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);

  dir = temp->dir_ptr;

  if (temp != NULL)
    result = dir_readdir(dir, name);
  return result;
}

static bool isdir (int fd) {
  struct fd_elem *temp;
  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);

  if (temp != NULL)
    return temp->isdir;
  else
    return false;
  
}

static int inumber (int fd) {
  struct fd_elem *temp;
  temp = NULL;
  temp = fd_list_iter(&thread_current()->fd_list, fd);

  if (temp != NULL)
    return inode_get_inumber(file_get_inode(temp->file_ptr));
  else
    return -1;
}


static int allocate_fd(void) {
  static int next_fd = 2;
  int fd;

  lock_acquire(&fd_lock);
  fd = next_fd++;
  lock_release(&fd_lock);

  return fd;
}

static mapid_t allocate_mid(void) {
  static mapid_t next_mid = 1;
  mapid_t mid;

  lock_acquire(&mid_lock);
  mid = next_mid++;
  lock_release(&mid_lock);

  return mid;
}


struct fd_elem *fd_list_iter (struct list *fd_list, int fd) {
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


static void lazy_file_map (void *vaddr, struct sup_page_table_entry *found_entry) {
  uint8_t *kpage = palloc_get_page (PAL_USER);
  struct thread *t = thread_current();
        
  if (kpage == NULL) {
    swap_out();
    kpage = palloc_get_page (PAL_USER);
  }

  if (file_read_at(found_entry->file_ptr, kpage, found_entry->page_read_bytes, found_entry->file_ofs) != (int)found_entry->page_read_bytes) {
    palloc_free_page(kpage);
  }

  memset (kpage + (found_entry->page_read_bytes), 0, PGSIZE - (found_entry->page_read_bytes));
  if (pagedir_get_page (t->pagedir, vaddr) == NULL)
    pagedir_set_page (t->pagedir, vaddr, kpage, found_entry->writable);
  allocate_frame(kpage, found_entry);
  found_entry->loaded = true;
}
