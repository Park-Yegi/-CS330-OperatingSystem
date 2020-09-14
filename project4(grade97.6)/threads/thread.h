#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/fixed_point.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"

typedef int mapid_t;

struct dir;

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int original_priority;              /* Priority before donation */
    int nice;                           /* Nice */
    fixed_point_t recent_cpu;           /* Recent CPU */
    struct list possessing_locks;       /* list of locks whose holder is this thread */
    struct lock *holded_by;             /* Lock which blocks this thread */
    int64_t waking_time;

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
    struct list_elem elem_all;          /* List element for all_list */
    struct list_elem elem_child;        /* List element for children_thread_list of parent */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct list children_thread_list;   /* list of children thread */
    struct semaphore parent_child_sync; /* Sema for returning exec after child's load */
    struct semaphore parent_wait_sema;  /* Sema for parent's waiting */
    int exit_status;                    /* Exit Status */
    struct thread *parent_thread;       /* Pointer of parent thread */
    struct list fd_list;                /* list of file descriptors */
    bool child_load_failed;             /* Flag to check if child load failed */
    struct list child_info_list;        /* List of child_info */
    void *file_ptr;                     /* File pointer if the thread loads a file */
    struct hash sup_page_table;         /* Hash table for spt */
    void *user_f_esp;                   /* Pointer to save stack ptr when switched from user to kernel (Pintos2.0.pdf, p.45)*/
    bool load_success;
    
#endif
    struct dir *curr_dir;               /* Current directory */
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

struct fd_elem {
  int fd;
  struct list_elem elem;
  struct file *file_ptr;
  struct dir *dir_ptr;
  uint32_t *vaddr;
  bool mmapped;
  bool isdir;
  mapid_t mapid;
};

struct child_info {
  tid_t tid;
  int exit_status;
  struct list_elem elem;
  bool exited;
  bool waited;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
void calc_recent_cpu(struct thread *);
int thread_get_load_avg (void);
void calc_load_avg(void);
bool less_waking_time(const struct list_elem *a, const struct list_elem *b, void *aux);
void waiting_list_push_back(struct list_elem *elem);
void wake_waiting_list(int64_t ticks);
bool less_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
int calc_priority(int recent_cpu, int nice);
int fix_to_int(fixed_point_t num);
void mlfqs_tick_change(int64_t timer_ticks);

#endif /* threads/thread.h */
