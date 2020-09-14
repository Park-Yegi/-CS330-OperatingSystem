#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"
#include "threads/thread.h"
#include <list.h>

/* Global Frame Table */
struct list frame_table;
struct lock frame_table_lock;

struct frame_table_entry
{
	uint32_t* frame;
	struct thread* owner;
	struct sup_page_table_entry* spte;
	struct list_elem elem;
	bool mmapped;
};

void frame_init (void);
bool allocate_frame (void *frame_addr, struct sup_page_table_entry *new_spte_ptr);

#endif /* vm/frame.h */
