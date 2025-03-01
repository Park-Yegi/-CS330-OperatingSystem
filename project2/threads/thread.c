#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed_point.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "filesys/file.h"
#endif


/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* Load average, initialized to 0 when booting. */
static fixed_point_t load_avg;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct list waiting_list;
static struct list all_list;	/* Save all threads. */

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */

/* This is 2016 spring cs330 skeleton code */

void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&waiting_list);
  list_init (&all_list);
  load_avg = CONVERT_N_TO_FIXED(0);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  struct child_info *new_child_info;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL) 
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  if (thread_mlfqs) {
    t->nice = thread_get_nice();
    t->recent_cpu = thread_get_recent_cpu();
    t->priority = calc_priority(t->recent_cpu, t->nice);
  }

  tid = t->tid = allocate_tid ();

  #ifdef USERPROG
    t->parent_thread = thread_current();
    if (strcmp(t->name, "idle")) {
      list_push_back(&thread_current()->children_thread_list, &t->elem_child);
      new_child_info = malloc(sizeof(struct child_info));
      new_child_info->tid = tid;
      new_child_info->exit_status = NULL;
      new_child_info->exited = false;
      new_child_info->waited = false;
      list_push_back(&thread_current()->child_info_list, &new_child_info->elem);
    }
  #endif

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;

  /* Add to run queue. */
  thread_unblock (t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  list_insert_ordered(&ready_list, &t->elem, &less_priority, NULL);
  t->status = THREAD_READY;

  if (thread_current() != idle_thread) {
    // if (thread_current()->priority < t->priority) {
    if (thread_current()->priority <= t->priority) {
      thread_yield();
    }
  }

  intr_set_level (old_level);  
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  struct list_elem *e, *e_next;
  struct lock_elem *l;
  struct child_info *c;
  struct fd_elem *f;
  
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Just set our status to dying and schedule another process.
     We will be destroyed during the call to schedule_tail(). */
  intr_disable ();
  struct thread *curr;
  curr = thread_current();

  file_close(curr->file_ptr);
  list_remove(&curr->elem_all);
  if (thread_current() != initial_thread) {
    list_remove(&curr->elem_child); 
  }

  /* free all lock_elem in possessing_locks malloced */
  if (!list_empty(&curr->possessing_locks)) {
    e = list_begin(&curr->possessing_locks);
    while (e!=list_end(&curr->possessing_locks)) {
      e_next = list_next(e);
      l = list_entry(e, struct lock_elem, elem);
      free(l);
      e = e_next;
    }
  }
  
  /* free all child_info in child_info_list malloced */
  if (!list_empty(&curr->child_info_list)) {
    e = list_begin(&curr->child_info_list);
    while (e!=list_end(&curr->child_info_list)) {
      e_next = list_next(e);
      c = list_entry(e, struct child_info, elem);
      free(c);
      e = e_next;
    }
  }

  /* free all fd_elem in fd_list malloced */
  if (!list_empty(&curr->fd_list)) {
    e = list_begin(&curr->fd_list);
    while (e!=list_end(&curr->fd_list)) {
      e_next = list_next(e);
      f = list_entry(e, struct fd_elem, elem);
      free(f);
      e = e_next;
    }
  }

  sema_up(&curr->parent_wait_sema);
  thread_current ()->status = THREAD_DYING;

  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *curr = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();

  if (curr != idle_thread) 
    list_insert_ordered(&ready_list, &curr->elem, &less_priority, NULL);

  curr->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  if (thread_mlfqs) {	/* If mlfqs, don't set priority. */
    return;
  }
  if (!list_empty(&thread_current()->possessing_locks)) {
    thread_current ()->original_priority = new_priority;
  }
  else {
    thread_current ()->priority = new_priority;
    thread_current ()->original_priority = new_priority;
  }

  if (!list_empty(&ready_list)) {
    struct thread *last_list_elem = list_entry(list_back(&ready_list), struct thread, elem);

    if (new_priority <= last_list_elem->priority) {
      thread_yield();
    }
  }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  enum intr_level old_level;

  old_level = intr_disable();
  if (nice > 20) {
    thread_current()->nice = 20;
  }
  else if (nice < -20) {
    thread_current()->nice = -20;
  }
  else {
    thread_current()->nice = nice;
  }
  calc_recent_cpu(thread_current());  
  thread_current()->priority = calc_priority(thread_current()->recent_cpu, thread_current()->nice);
  thread_yield();
  intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return ROUND_TO_NEAR(MULT_X_N(load_avg, 100));
}

/* Calculate new load average. */
void
calc_load_avg (void)
{
  fixed_point_t converted_59, result, converted_1, temp1, temp2;

  temp1 = DIV_X_N(MULT_X_N(load_avg, 59),60);

  if (thread_current() == idle_thread) {
    temp2 = DIV_X_N(CONVERT_N_TO_FIXED(list_size(&ready_list)), 60);
    result = ADD_X_Y(temp1, temp2);
  } else {
    temp2 = DIV_X_N(CONVERT_N_TO_FIXED(list_size(&ready_list)+1), 60);
    result = ADD_X_Y(temp1, temp2); 
  }

  load_avg = result;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return ROUND_TO_NEAR(MULT_X_N(thread_current()->recent_cpu, 100));
}

void
calc_recent_cpu(struct thread *t)
{
  fixed_point_t converted_load_avg, result, temp1, temp2;
  converted_load_avg = MULT_X_N(load_avg, 2);
  temp1 = DIV_X_Y(converted_load_avg, ADD_X_N(converted_load_avg, 1));
  result = ADD_X_N(MULT_X_Y(temp1, t->recent_cpu), t->nice);
  t->recent_cpu = result;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);
                    
  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Since `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->original_priority = priority;
  t->magic = THREAD_MAGIC;
  t->holded_by = NULL;
  list_init(&t->possessing_locks);
  t->nice = 0;
  t->recent_cpu = 0;

  #ifdef USERPROG
    list_init(&t->children_thread_list);
    sema_init(&t->parent_child_sync, 0);
    sema_init(&t->parent_wait_sema, 0);
    t->exit_status = NULL;
    list_init(&t->fd_list);
    t->child_load_failed = NULL;
    list_init(&t->child_info_list);
    t->file_ptr = NULL;
  #endif
  
  list_push_back(&all_list, &t->elem_all);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else {
    return list_entry (list_pop_back (&ready_list), struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
schedule_tail (struct thread *prev) 
{
  struct thread *curr = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  curr->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != curr);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.
   
   It's not safe to call printf() until schedule_tail() has
   completed. */
static void
schedule (void) 
{
  struct thread *curr = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (curr->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (curr != next)
    prev = switch_threads (curr, next);
  schedule_tail (prev); 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

bool less_waking_time(const struct list_elem *a,
	  const struct list_elem *b,
	  void *aux) {
  struct thread *t_a = list_entry(a, struct thread, elem);
  struct thread *t_b = list_entry(b, struct thread, elem);
  return t_a->waking_time <= t_b->waking_time;
}

void waiting_list_push_back(struct list_elem *e) {
  struct thread *t = list_entry(e, struct thread, elem);
  list_insert_ordered(&waiting_list, e, &less_waking_time, NULL);
}

void wake_waiting_list(int64_t ticks) {
  struct list_elem *e;
  struct list_elem *e_next;
  enum intr_level old_level;

  if (!list_empty(&waiting_list)) {
    
    e = list_begin(&waiting_list);
    while (e != list_end(&waiting_list)) {
      struct thread *t = list_entry(e, struct thread, elem);
      if (t->waking_time <= ticks && t->status == THREAD_BLOCKED) {
        old_level = intr_disable();
      	e_next = list_next(e);
	      list_pop_front(&waiting_list);

        list_insert_ordered(&ready_list, &t->elem, &less_priority, NULL);
        t->status = THREAD_READY;
        intr_set_level(old_level);
      }
      else {
        e_next = list_next(e);
      }
      e = e_next;
    }
  }
}

bool less_priority(const struct list_elem *a,
	  const struct list_elem *b,
	  void *aux) {
  struct thread *t_a = list_entry(a, struct thread, elem);
  struct thread *t_b = list_entry(b, struct thread, elem);
  return t_a->priority <= t_b->priority;
}

int calc_priority(fixed_point_t recent_cpu, int nice) {
  fixed_point_t converted_pri_max, converted_recent_cpu, result;
  converted_pri_max = CONVERT_N_TO_FIXED(PRI_MAX);
  converted_recent_cpu = DIV_X_N(recent_cpu, 4);
  result = SUBTRACT_X_N(SUBTRACT_X_Y(converted_pri_max, converted_recent_cpu), 2*nice);
  result = ROUND_TO_ZERO(result);
  
  if (result < PRI_MIN) {
    return PRI_MIN;
  }
  else if (result > PRI_MAX) {
    return PRI_MAX;
  }
  else {
    return result;
  }
}

int fix_to_int(fixed_point_t num) {
  num = num >> 14;		/* Remove fraction zeros. */
  return num & 0x8001FFFF;	/* Fix sign bit. */
}

void mlfqs_tick_change(int64_t timer_ticks) {
    enum intr_level old_level;
    struct list_elem *e;
    struct thread *t;

    if (thread_current() != idle_thread) {
      fixed_point_t old_recent_cpu;
      old_recent_cpu = thread_current()->recent_cpu;
      thread_current()->recent_cpu = ADD_X_N(old_recent_cpu, 1);
    }


    if ((timer_ticks % 100) == 0) {
      calc_load_avg();

      for(e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)){
        t = list_entry(e, struct thread, elem_all);
        if (t != idle_thread) {
          calc_recent_cpu(t);
        }
      }
    }

    if ((timer_ticks % 4) == 0) {
      for(e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)){
        t = list_entry(e, struct thread, elem_all);
        if (t != idle_thread) {
          t->priority = calc_priority(t->recent_cpu, t->nice);
        }
      }
    }
}
