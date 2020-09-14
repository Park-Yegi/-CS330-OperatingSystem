#include "devices/disk.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "filesys/inode.h"


struct cache_block {
    struct semaphore block_sema;
    disk_sector_t sector;               /* Sector number of disk location. */
    bool dirty;
    bool access;
    char data[512];
    iid_t holder;
    int pos;
};

void cache_init();
void inode_put_cache (void *src, disk_sector_t sec_id, iid_t iid, int pos, int sector_ofs, int chunk_size);
void inode_get_cache (void *dest, disk_sector_t sec_id, iid_t iid, int pos, int sector_ofs, int chunk_size);
off_t cache_write_disk (struct disk *d, disk_sector_t sec_id, iid_t iid, off_t size, off_t offset);
off_t cache_read_disk (struct disk *d, disk_sector_t sec_id, int cache_id, off_t size, off_t offset);

int get_cache_holder (int cache_idx);

