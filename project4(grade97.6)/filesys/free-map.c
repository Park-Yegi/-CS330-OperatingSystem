#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

static struct file *free_map_file;   /* Free map file. */
static struct bitmap *free_map;      /* Free map, one bit per disk sector. */

/* Initializes the free map. */
void
free_map_init (void) 
{
  free_map = bitmap_create (disk_size (filesys_disk));
  if (free_map == NULL)
    PANIC ("bitmap creation failed--disk is too large");
  bitmap_mark (free_map, FREE_MAP_SECTOR);
  bitmap_mark (free_map, ROOT_DIR_SECTOR);
}

/* Allocates CNT consecutive sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if all sectors were
   available. */
bool
free_map_allocate (size_t cnt, disk_sector_t *sectorp) 
{
  disk_sector_t sector = bitmap_scan_and_flip (free_map, 0, cnt, false);
  if (sector != BITMAP_ERROR
      && free_map_file != NULL
      && !bitmap_write (free_map, free_map_file))
    {
      bitmap_set_multiple (free_map, sector, cnt, false); 
      sector = BITMAP_ERROR;
    }
  if (sector != BITMAP_ERROR)
    *sectorp = sector;
  return sector != BITMAP_ERROR;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void
free_map_release (disk_sector_t sector, size_t cnt)
{
  ASSERT (bitmap_all (free_map, sector, cnt));
  bitmap_set_multiple (free_map, sector, cnt, false);
  bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk. */
void
free_map_open (void) 
{
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_read (free_map, free_map_file))
    PANIC ("can't read free map");
}

/* Writes the free map to disk and closes the free map file. */
void
free_map_close (void) 
{
  file_close (free_map_file);
}

/* Creates a new free map file on disk and writes the free map to
   it. */
void
free_map_create (void) 
{
  /* Create inode. */
  if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map), true))
    PANIC ("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_write (free_map, free_map_file))
    PANIC ("can't write free map");
}


bool
free_map_allocate_index (size_t start, size_t cnt, disk_sector_t *direct, disk_sector_t *indirect, disk_sector_t *doubly_indirect, disk_sector_t *indirect_arr, disk_sector_t *parent_arr, disk_sector_t **doubly_arr) 
{
  int i, temp;
  disk_sector_t sector, indirect_sector;

  // for (i=0; i<cnt; i++) {
  for (i=start; i<cnt+start; i++) {
    sector = bitmap_scan_and_flip (free_map, 0, 1, false);
    if (sector != BITMAP_ERROR
        && free_map_file != NULL
        && !bitmap_write (free_map, free_map_file))
      {
        bitmap_set (free_map, sector, false); 
        sector = BITMAP_ERROR;
        return false;
      }
    if (sector != BITMAP_ERROR) {
      if (i<DIRECT_LEN) {
        direct[i] = sector;
      } else if (i == DIRECT_LEN) {
        *indirect = sector;
        indirect_sector = bitmap_scan_and_flip (free_map, 0, 1, false);
        if (indirect_sector != BITMAP_ERROR
            && free_map_file != NULL
            && !bitmap_write (free_map, free_map_file))
          {
            bitmap_set (free_map, indirect_sector, false); 
            indirect_sector = BITMAP_ERROR;
            return false;
          }
        indirect_arr[0] = indirect_sector;
      } else if (i < DIRECT_LEN+128) {
        indirect_arr[i-DIRECT_LEN] = sector;
      } else if (i == DIRECT_LEN+128) {
        *doubly_indirect = sector;

        indirect_sector = bitmap_scan_and_flip (free_map, 0, 1, false);
        if (indirect_sector != BITMAP_ERROR
            && free_map_file != NULL
            && !bitmap_write (free_map, free_map_file))
          {
            bitmap_set (free_map, indirect_sector, false); 
            indirect_sector = BITMAP_ERROR;
            return false;
          }
        parent_arr[0] = indirect_sector;

        indirect_sector = bitmap_scan_and_flip (free_map, 0, 1, false);
        if (indirect_sector != BITMAP_ERROR
            && free_map_file != NULL
            && !bitmap_write (free_map, free_map_file))
          {
            bitmap_set (free_map, indirect_sector, false); 
            indirect_sector = BITMAP_ERROR;
            return false;
          }
        *doubly_arr = indirect_sector;
      } else {
        temp = i-DIRECT_LEN-128;
        if (temp%128 == 0) {
          parent_arr[temp/128] = sector;
          indirect_sector = bitmap_scan_and_flip (free_map, 0, 1, false);
          if (indirect_sector != BITMAP_ERROR
              && free_map_file != NULL
              && !bitmap_write (free_map, free_map_file))
            {
              bitmap_set (free_map, indirect_sector, false); 
              indirect_sector = BITMAP_ERROR;
              return false;
            }
          *(doubly_arr+temp) = indirect_sector;
        } else {
          *(doubly_arr+temp) = sector;
        }
      }
    }
  }

  return true;
}