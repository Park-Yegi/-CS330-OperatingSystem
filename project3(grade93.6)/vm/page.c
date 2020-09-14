#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <hash.h>

/*
 * Initialize supplementary page table
 */
void 
page_init (void)
{
    hash_init(&thread_current()->sup_page_table, page_hash, page_less, NULL);
}

/*
 * Make new supplementary page table entry for addr 
 */
struct sup_page_table_entry *
allocate_page (void *addr)
{
    struct sup_page_table_entry *new_entry;
    new_entry = malloc(sizeof(struct sup_page_table_entry));

    new_entry -> user_vaddr = addr;
    new_entry -> access_time = NULL; 

    new_entry -> swapped = false;
    new_entry -> dirty = false;
    new_entry -> accessed = false;

    new_entry -> load_executable = false;

    new_entry -> mmapped = false;

    hash_insert(&thread_current()->sup_page_table, &new_entry->hash_elem);

    return &new_entry;
}

/*********** Helper functions for using hash table ***********/
/*********** Reference: pintos 2.0 document A.8.5 ************/
unsigned
page_hash (const struct hash_elem *p_, void *aux)
{
    const struct sup_page_table_entry *p = hash_entry (p_, struct sup_page_table_entry, hash_elem);
    return hash_bytes (&p->user_vaddr, sizeof(p->user_vaddr));
}

bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
    const struct sup_page_table_entry *a = hash_entry(a_, struct sup_page_table_entry, hash_elem);
    const struct sup_page_table_entry *b = hash_entry(b_, struct sup_page_table_entry, hash_elem);

    return a->user_vaddr < b->user_vaddr;
}

/**********Funtion to find sup_page_table_entry with user_vaddr ********/
struct sup_page_table_entry *
page_lookup (const void *address) {
    struct sup_page_table_entry p;
    struct hash_elem *e;

    p.user_vaddr = address;
    e = hash_find(&thread_current()->sup_page_table, &p.hash_elem);
    return e != NULL? hash_entry(e, struct sup_page_table_entry, hash_elem) : NULL;
}

void page_free (struct hash_elem *e, void *aux) {
    struct sup_page_table_entry *spte;
    spte = hash_entry(e, struct sup_page_table_entry, hash_elem);
    free(spte);
}
