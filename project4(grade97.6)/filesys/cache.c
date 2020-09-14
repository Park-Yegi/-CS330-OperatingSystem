#include "filesys/cache.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"

static struct cache_block buffer_cache[64];
static struct lock evict_lock;

static int search_free_block();
static int search_free_block_multiple(int cnt);
static int cache_evict ();
static int sector_to_cachei (disk_sector_t sector);
static int find_cache_by_iid (iid_t iid);
static int find_me (iid_t iid, disk_sector_t sec_id, int pos);

void cache_init() {
    int i;
    for (i=0; i<64; i++) {
        buffer_cache[i].holder = NULL;
        buffer_cache[i].sector = -1;
        sema_init(&buffer_cache[i].block_sema, 1);
    }
    lock_init(&evict_lock);
}

void inode_put_cache (void *src, disk_sector_t sec_id, iid_t iid, int pos, int sector_ofs, int chunk_size) {
  bool already_cached = true;
  int sector_left = DISK_SECTOR_SIZE - sector_ofs;

  int cache_id = find_me(iid, sec_id, pos);
  if (cache_id == -1) {
    already_cached = false;

    cache_id = search_free_block();
    if (cache_id == -1) {
      lock_acquire(&evict_lock);
      cache_id = cache_evict();
      lock_release(&evict_lock);
    }
  }

  sema_down(&buffer_cache[cache_id].block_sema);

  if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
    memcpy(buffer_cache[cache_id].data, src, 512);
  }
  else {
    if (!already_cached) 
      memset(buffer_cache[cache_id].data, 0, DISK_SECTOR_SIZE);
    memcpy(buffer_cache[cache_id].data+sector_ofs, src, chunk_size);
  }

  buffer_cache[cache_id].sector = sec_id;
  buffer_cache[cache_id].pos = pos;
  if (!already_cached) {
    buffer_cache[cache_id].dirty = 0;
    buffer_cache[cache_id].access = 0;
    buffer_cache[cache_id].holder = iid;
  } else {
    buffer_cache[cache_id].dirty = 1;
  }

  sema_up(&buffer_cache[cache_id].block_sema);
}


void inode_get_cache (void *dest, disk_sector_t sec_id, iid_t iid, int pos, int sector_ofs, int chunk_size) {
  int cache_id = sector_to_cachei(sec_id);

  if ((cache_id == -1) || ((buffer_cache[cache_id].holder != iid)&&(iid!=-3))) {
    cache_id = search_free_block();

    if (cache_id == -1) {
      lock_acquire(&evict_lock);
      cache_id = cache_evict();
      lock_release(&evict_lock);
    }

    sema_down(&buffer_cache[cache_id].block_sema);
    cache_read_disk(filesys_disk, sec_id, cache_id, 512, 0); 
    buffer_cache[cache_id].pos = pos;
  }
  else {
    sema_down(&buffer_cache[cache_id].block_sema);
  }

  if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
    memcpy(dest, buffer_cache[cache_id].data, 512);
  }
  else {
    memcpy(dest, buffer_cache[cache_id].data+sector_ofs, chunk_size);
  }

  buffer_cache[cache_id].access = true;

  sema_up(&buffer_cache[cache_id].block_sema);
}


off_t cache_write_disk (struct disk *d, disk_sector_t sec_id, int cache_id, off_t size, off_t offset) {
  off_t bytes_written = 0;
  const off_t length = size;
  const disk_sector_t original_sec = sec_id;
  disk_sector_t current_sec;
  iid_t curr_id = cache_id;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      current_sec = original_sec + (offset / DISK_SECTOR_SIZE);
      int cache_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = DISK_SECTOR_SIZE - cache_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      disk_write (d, current_sec, buffer_cache[curr_id].data); 

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      curr_id++;
    }

  return bytes_written;
}

off_t cache_read_disk (struct disk *d, disk_sector_t sec_id, int cache_id, off_t size, off_t offset) {
    off_t bytes_read = 0;
    const off_t length = size;
    const disk_sector_t original_sec = sec_id;
    disk_sector_t current_sec;
    iid_t curr_id = cache_id;

    while (size > 0) 
    {
      current_sec = original_sec + (offset / DISK_SECTOR_SIZE);
      int cache_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = DISK_SECTOR_SIZE - cache_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      disk_read (d, current_sec, buffer_cache[curr_id].data);

      buffer_cache[curr_id].access = 0;
      buffer_cache[curr_id].dirty = 0;
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
      curr_id++;
    }

    return bytes_read;
}

int get_cache_holder (int cache_idx) {
    return buffer_cache[cache_idx].holder;
}

// Search consecutive free blocks
static int search_free_block_multiple(int cnt) {
    int i, j;

    for (i=0; i<64; i++) {
        if ((i+cnt) >= 64)
            return -1;
        if (buffer_cache[i].holder == NULL) {
            for (j=0; j<cnt; j++) {
                if (buffer_cache[i+j].holder != NULL) {
                    i += j;
                    break;
                }
            }
            if (j == cnt)
                return i;
        }
    }
    return -1;
}

static int search_free_block() {
    int i, j;

    for (i=0; i<64; i++) {
        if (buffer_cache[i].holder == NULL)
          return i;
    }
    return -1;
}


static int sector_to_cachei (disk_sector_t sector) {
    int i;
    for (i = 0; i < 64; i++) {
        if (buffer_cache[i].sector == sector) {
            return i;
        }
    }
    return -1;
}


static int find_cache_by_iid (iid_t iid) {
    int i;
    for (i = 0; i < 64; i++) {
        if (buffer_cache[i].holder == iid) {
            return i;
        }
    }
    return -1;
}

static int find_me (iid_t iid, disk_sector_t sec_id, int pos) {  // Compare both iid and sec_id
    int i;
    for (i = 0; i < 64; i++) {
        if (buffer_cache[i].holder == iid && buffer_cache[i].sector == sec_id && buffer_cache[i].pos == pos) {
            return i;
        }
    }
    return -1;
}

static int cache_evict () {
  static int victim = 0;

  victim = victim%64;

  if (buffer_cache[victim].dirty)
    cache_write_disk (filesys_disk, buffer_cache[victim].sector, victim, 512, 0);
  buffer_cache[victim].holder = NULL;
  buffer_cache[victim].sector = -1;

  victim++;

  return victim-1;
}

