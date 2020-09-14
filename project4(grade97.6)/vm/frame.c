#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/*
 * Initialize frame table
 */
void 
frame_init (void)
{
    list_init(&frame_table);
    lock_init(&frame_table_lock);
}


/* 
 * Make a new frame table entry for addr.
 */
bool
allocate_frame (void *frame_addr, struct sup_page_table_entry *new_spte_ptr)
{
    struct frame_table_entry *new_entry;

    new_entry = malloc(sizeof(struct frame_table_entry));
    new_entry -> frame = frame_addr;
    new_entry -> owner = thread_current();
    new_entry -> spte = new_spte_ptr;
    new_entry -> mmapped = false;

    list_push_back(&frame_table, &new_entry->elem);
    
    return true;
}

