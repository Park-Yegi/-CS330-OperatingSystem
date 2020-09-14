#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "devices/disk.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include <bitmap.h>
#include <list.h>
#include <string.h>


/* The swap device */
static struct disk *swap_device;

/* Tracks in-use and free swap slots */
static struct bitmap *swap_table;

/* Protects swap_table */
static struct lock swap_lock;

/* 
 * Initialize swap_device, swap_table, and swap_lock.
 */
void 
swap_init (void)
{
    swap_device = disk_get(1, 1);
    swap_table = bitmap_create(8192);   // 4MB/512 sectors (sector size:512B, disk size 4MB)
    lock_init(&swap_lock);
}

/*
 * Reclaim a frame from swap device.
 * 1. Check that the page has been already evicted. 
 * 2. You will want to evict an already existing frame
 * to make space to read from the disk to cache. 
 * 3. Re-link the new frame with the corresponding supplementary
 * page table entry. 
 * 4. Do NOT create a new supplementray page table entry. Use the 
 * already existing one. 
 * 5. Use helper function read_from_disk in order to read the contents
 * of the disk into the frame. 
 */ 
bool 
swap_in (void *vaddr, uint8_t *kpage)
{
    lock_acquire(&swap_lock);
    struct sup_page_table_entry *spte;
    
    // 1
    spte = page_lookup(vaddr);
    if (spte->swapped == false)
        return false;
    
    // 2
    // Assume a frame is already evicted in function swap_out()

    // 3
    allocate_frame(kpage, spte);

    // 4
    spte->swapped = false;

    // 5
    if (spte->mmapped) {
        file_read_at(spte->file_ptr, kpage, spte->page_read_bytes, spte->file_ofs);
        memset (kpage + (spte->page_read_bytes), 0, PGSIZE - (spte->page_read_bytes));
    }
    else if (!spte->load_executable || spte->writable) {
        read_from_disk(kpage, spte->disk_sector_idx);
        bitmap_set_multiple(swap_table, spte->disk_sector_idx, 8, 0);
    }
    else {
        file_read_at(spte->file_ptr, kpage, spte->page_read_bytes, spte->file_ofs);
        memset (kpage + (spte->page_read_bytes), 0, PGSIZE - (spte->page_read_bytes));
    }
    lock_release(&swap_lock);
    return true;
}

/* 
 * Evict a frame to swap device. 
 * 1. Choose the frame you want to evict. 
 * (Ex. Least Recently Used policy -> Compare the timestamps when each 
 * frame is last accessed)
 * 2. Evict the frame. Unlink the frame from the supplementray page table entry
 * Remove the frame from the frame table after freeing the frame with
 * pagedir_clear_page. 
 * 3. Do NOT delete the supplementary page table entry. The process
 * should have the illusion that they still have the page allocated to
 * them. 
 * 4. Find a free block to write you data. Use swap table to get track
 * of in-use and free swap slots.
 */
bool
swap_out (void)
{
    lock_acquire(&swap_lock);
    struct list_elem *e;
    struct frame_table_entry *fte;
    struct sup_page_table_entry *spte;
    struct thread *t = thread_current();
    size_t starting_idx;

    // 1
    e = list_pop_front(&frame_table);
    if (e == NULL) {
        return false;
    }
    fte = list_entry(e, struct frame_table_entry, elem);

    // 2, 3
    spte = fte->spte;
    spte->swapped = true;
    pagedir_clear_page(t->pagedir, spte->user_vaddr);

    // 4
    if (spte->mmapped) {
        if (spte->dirty) {
            lock_acquire(&filesys_lock);
            file_write_at(spte->file_ptr, spte->user_vaddr, spte->page_read_bytes, spte->file_ofs);
            lock_release(&filesys_lock);
        }
    }
    else if (!spte->load_executable || spte->writable) {
        starting_idx = bitmap_scan(swap_table, 0, 8, 0);
        write_to_disk(fte->frame, starting_idx);
        bitmap_set_multiple(swap_table, starting_idx, 8, 1);
        spte->disk_sector_idx = starting_idx;
    }

    palloc_free_page(fte->frame);
    free(fte);
    lock_release(&swap_lock);
    return true;
}

/* 
 * Read data from swap device to frame. 
 * Look at device/disk.c
 */
void read_from_disk (uint8_t *frame, int index)
{
    int i;

    for (i=0; i<8; i++) 
        disk_read(swap_device, index+i, frame+ (512*i));
}

/* Write data to swap device from frame */
void write_to_disk (uint8_t *frame, int index)
{
    int i;
    
    for (i=0; i<8; i++)
        disk_write(swap_device, index+i, frame+ (512*i));
}
