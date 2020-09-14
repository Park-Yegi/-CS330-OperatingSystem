#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


static struct lock iid_lock;
static iid_t allocate_iid (void);
static void add_blocks(struct inode *inode, off_t new_eof, off_t old_eof);
static void fill_zeros(struct inode *inode, off_t old_eof, off_t offset);

disk_sector_t indirect_sec_idx[128];
disk_sector_t doubly_sec_parent[128];
disk_sector_t doubly_sec_idx[128][128];

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    iid_t inode_i;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    bool isdir;
    disk_sector_t direct_block[DIRECT_LEN];
    disk_sector_t indirect_block;
    disk_sector_t doubly_indirect_block;
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    int cache_index;
    iid_t inode_id;
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&iid_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  int i;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->inode_i = allocate_iid();
      disk_inode->isdir = isdir;
      if (free_map_allocate_index (0, sectors, disk_inode->direct_block, &disk_inode->indirect_block, &disk_inode->doubly_indirect_block, indirect_sec_idx, doubly_sec_parent, doubly_sec_idx))
        {
          disk_write (filesys_disk, sector, disk_inode);
          if (sectors > DIRECT_LEN)
            disk_write(filesys_disk, disk_inode->indirect_block, indirect_sec_idx);
          if (sectors > DIRECT_LEN+128) {
            disk_write(filesys_disk, disk_inode->doubly_indirect_block, doubly_sec_parent);
            disk_write(filesys_disk, doubly_sec_parent[0], doubly_sec_idx[0]);
          
            for (i=1; i<=(sectors-DIRECT_LEN-128)/128; i++)
              disk_write(filesys_disk, doubly_sec_parent[i], doubly_sec_idx[i]);
          }

          // inode_put_cache(disk_inode, sector, disk_inode->inode_i, 0, 0, 512);
          if (sectors > 0) 
            {
              static char zeros[DISK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) {
                if (i < DIRECT_LEN) {              // Direct block
                  disk_write (filesys_disk, disk_inode->direct_block[i], zeros); 
                } else if (i < DIRECT_LEN+128) {   // Indirection block
                  disk_write (filesys_disk, indirect_sec_idx[i-DIRECT_LEN], zeros);
                } else {
                  disk_write (filesys_disk, doubly_sec_idx[(i-DIRECT_LEN-128)/128][(i-DIRECT_LEN-128)%128], zeros);
                }
              }
                // disk_write (filesys_disk, disk_inode->start + i, zeros); 
                // inode_put_cache (zeros, disk_inode->start + i, disk_inode->inode_i, i, 0, 512);
            }

          memset(indirect_sec_idx, 0, 512);
          memset(doubly_sec_parent, 0, 512);
          memset(doubly_sec_idx, 0, 512*128);

          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->cache_index = -1;
  inode->inode_id = -3;
  disk_read (filesys_disk, inode->sector, &inode->data);
  // inode_get_cache (&inode->data, inode->sector, inode->inode_id, 0, 0, 512);
  inode->inode_id = inode->data.inode_i;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

bool
inode_get_isdir (const struct inode *inode)
{
  return inode->data.isdir;
}

bool
inode_get_isremoved (const struct inode *inode)
{
  return inode->removed;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
bool   //void
inode_close (struct inode *inode) 
{
  int i, j;
  int num_blocks;
  disk_sector_t buffer[128];
  disk_sector_t buffer_child[128];
  /* Ignore null pointer. */
  if (inode == NULL)
    return false;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          int round_up =  (inode->data.length % DISK_SECTOR_SIZE) ? 1 :0;
          num_blocks = (inode->data.length / DISK_SECTOR_SIZE)+round_up;

          // Free direct blocks
          for (i=0; i<(num_blocks < DIRECT_LEN? num_blocks:DIRECT_LEN); i++)
            free_map_release (inode->data.direct_block[i], 1);
          
          // Free indirect blocks (including parent node)
          if (num_blocks > DIRECT_LEN){
            disk_read (filesys_disk, inode->data.indirect_block, buffer);
            free_map_release (inode->data.indirect_block, 1);
            free_map_release (buffer[0], 1);
            for (i=1; i<=(num_blocks-DIRECT_LEN); i++)
              free_map_release (buffer[i], 1);
          }

          // Free doubly indirect blocks including parent nodes
          if (num_blocks > DIRECT_LEN + 128) {
            disk_read (filesys_disk, inode->data.doubly_indirect_block, buffer);
            free_map_release (inode->data.doubly_indirect_block, 1);
            for (i=0; i<=(num_blocks-DIRECT_LEN-128)/128; i++) {
              disk_read (filesys_disk, buffer[i], buffer_child);
              free_map_release (buffer[i], 1);
              for (j=0; j<=(num_blocks-DIRECT_LEN-128)%128; j++)
                free_map_release (buffer_child[j], 1);
            }
          }
        }

      free (inode); 
      return true;
    }
  return false;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  /*********** Initial code ***********/
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  disk_sector_t sector_idx;
  disk_sector_t index_buffer[128];
  disk_sector_t index_parent_buffer[128];
  int buffer_flag = -1;
  bool buffer_parent_flag = false;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      // disk_sector_t sector_idx = byte_to_sector (inode, offset);

      off_t off_div_size = offset/512;
      if (off_div_size < DIRECT_LEN) {           // Direct block
        sector_idx = inode->data.direct_block[off_div_size];
      }
      else if (off_div_size < DIRECT_LEN+128) {  // Indirect block
        if (buffer_flag != 128) {
          disk_read(filesys_disk, inode->data.indirect_block, index_buffer);
          buffer_flag = 128;
        }
        sector_idx = index_buffer[off_div_size-DIRECT_LEN];
      } else {                                    // Doubly indirect block
        if (!buffer_parent_flag) {
          disk_read(filesys_disk, inode->data.doubly_indirect_block, index_parent_buffer);
          buffer_parent_flag = true;
        }

        if (buffer_flag != (off_div_size - DIRECT_LEN-128)/128) {
          disk_read (filesys_disk, index_parent_buffer[(off_div_size - DIRECT_LEN-128)/128], index_buffer);
          buffer_flag = (off_div_size - DIRECT_LEN-128)/128;
        }
        sector_idx = index_buffer[(off_div_size - DIRECT_LEN-128)%128];
      }

      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
          disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          disk_read (filesys_disk, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      // inode_get_cache(buffer + bytes_read, sector_idx, inode->inode_id, offset/512, sector_ofs, chunk_size);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  /***********************************************/

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  disk_sector_t sector_idx;
  disk_sector_t index_buffer[128];
  disk_sector_t index_parent_buffer[128];
  int buffer_flag = -1;
  bool buffer_parent_flag = false;
  int round_up;

  if (inode->deny_write_cnt)
    return 0;

  if (inode->data.length < (offset+size)) { 
    round_up = inode->data.length%512 ? 1:0;
    if ( (((inode->data.length/512)+round_up)*512)  < offset+size ) {   // Adding blocks is needed?
      add_blocks(inode, offset+size, inode->data.length);
    }
    fill_zeros(inode, inode->data.length, offset);
    memset(indirect_sec_idx, 0, 512);
    memset(doubly_sec_parent, 0, 512);
    memset(doubly_sec_idx, 0, 512*128);
    inode->data.length = offset+size;
    disk_write (filesys_disk, inode->sector, &inode->data);
  }

  /**************** Initial code ******************/
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      // disk_sector_t sector_idx = byte_to_sector (inode, offset);

      off_t off_div_size = offset/512;
      if (off_div_size < DIRECT_LEN) {           // Direct block
        sector_idx = inode->data.direct_block[off_div_size];
      }
      else if (off_div_size < DIRECT_LEN+128) {  // Indirect block
        if (buffer_flag != 128) {
          disk_read(filesys_disk, inode->data.indirect_block, index_buffer);
          buffer_flag = 128;
        }
        sector_idx = index_buffer[off_div_size-DIRECT_LEN];
      } else {                                    // Doubly indirect block
        if (!buffer_parent_flag) {
          disk_read(filesys_disk, inode->data.doubly_indirect_block, index_parent_buffer);
          buffer_parent_flag = true;
        }

        if (buffer_flag != (off_div_size - DIRECT_LEN-128)/128) {
          disk_read (filesys_disk, index_parent_buffer[(off_div_size - DIRECT_LEN-128)/128], index_buffer);
          buffer_flag = (off_div_size - DIRECT_LEN-128)/128;
        }
        sector_idx = index_buffer[(off_div_size - DIRECT_LEN-128)%128];
      }
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
          disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            disk_read (filesys_disk, sector_idx, bounce);
          else
            memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          disk_write (filesys_disk, sector_idx, bounce); 
        }
      // inode_put_cache(buffer+bytes_written, sector_idx, inode->inode_id, offset/512, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  /*********************************************/

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


static iid_t
allocate_iid (void) 
{
  static iid_t next_iid = 1;
  iid_t iid;

  lock_acquire (&iid_lock);
  iid = next_iid++;
  lock_release (&iid_lock);

  return iid;
}

static void 
add_blocks(struct inode *inode, off_t new_eof, off_t old_eof) {
  int i;
  int round_up, round_down;
  round_up = old_eof%512? 1:0;
  round_down = old_eof%512? 0:1;

  if ((old_eof/512) > DIRECT_LEN){
    disk_read(filesys_disk, inode->data.indirect_block, indirect_sec_idx);
  }
  if ((old_eof/512) > DIRECT_LEN+128) {
    disk_read(filesys_disk, inode->data.doubly_indirect_block, doubly_sec_parent);
    for (i=0; i<((old_eof/512)-DIRECT_LEN-128)/128; i++) {
      disk_read(filesys_disk, doubly_sec_parent[i], doubly_sec_idx[i]);
    }
  }

  if (free_map_allocate_index((old_eof/512)+round_up,
                              (new_eof/512)-(old_eof/512)+round_down,
                              inode->data.direct_block,
                              &inode->data.indirect_block,
                              &inode->data.doubly_indirect_block,
                              indirect_sec_idx,
                              doubly_sec_parent,
                              doubly_sec_idx)) {
    // disk_write (filesys_disk, inode->sector, &inode->data);
    if ((new_eof/512) > DIRECT_LEN)
      disk_write(filesys_disk, inode->data.indirect_block, indirect_sec_idx);
    if ((new_eof/512) > DIRECT_LEN+128) {
      disk_write(filesys_disk, inode->data.doubly_indirect_block, doubly_sec_parent);
      disk_write(filesys_disk, doubly_sec_parent[0], doubly_sec_idx[0]);
          
      for (i=1; i<=((new_eof/512)-DIRECT_LEN-128)/128; i++)
        disk_write(filesys_disk, doubly_sec_parent[i], doubly_sec_idx[i]);
    }
  }
}

static void 
fill_zeros(struct inode *inode, off_t old_eof, off_t offset) {
  static char zeros[DISK_SECTOR_SIZE] = { 0,};
  char buffer[DISK_SECTOR_SIZE];
  disk_sector_t sector_idx;
  off_t chunk_size;

  off_t size = offset - old_eof -1; // offset-old_eof

  while (size > 0) {
    off_t off_div_size = old_eof/512;
    if (off_div_size < DIRECT_LEN)          // Direct block
      sector_idx = inode->data.direct_block[off_div_size];
    else if (off_div_size < DIRECT_LEN+128) // Indirect block
      sector_idx = indirect_sec_idx[off_div_size-DIRECT_LEN];
    else                                    // Doubly indirect block
      sector_idx = doubly_sec_idx[(off_div_size - DIRECT_LEN-128)/128][(off_div_size - DIRECT_LEN-128)%128];

    chunk_size = 512-(old_eof%512);

    if (old_eof % 512 == 0) {
      disk_write(filesys_disk, sector_idx, zeros);
    }
    else {
      disk_read(filesys_disk, sector_idx, buffer);
      memset(buffer+(old_eof%512), 0, chunk_size);
      disk_write(filesys_disk, sector_idx, buffer);
    }

    old_eof += chunk_size;
    size -= chunk_size;
  }
}
