#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "userprog/syscall.h"

struct sup_page_table_entry 
{
	uint32_t* user_vaddr;
	uint64_t access_time;

	bool swapped;
	bool dirty;
	bool accessed;
	struct hash_elem hash_elem;
	size_t disk_sector_idx;

	bool load_executable;
	bool loaded;
	size_t page_read_bytes;
	off_t file_ofs;
	bool writable;

	// elements for mapping files
	bool mmapped;
	mapid_t mid;
	int fd;
	struct file *file_ptr;
	int page_cnt;
};

void page_init (void);
struct sup_page_table_entry *allocate_page (void *addr);
struct sup_page_table_entry *page_lookup (const void *address);
unsigned page_hash (const struct hash_elem *p_, void *aux);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
void page_free (struct hash_elem *e, void *aux);
#endif /* vm/page.h */
