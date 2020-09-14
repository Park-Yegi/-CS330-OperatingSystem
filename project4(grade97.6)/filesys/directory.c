#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "devices/disk.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    disk_sector_t inode_sector;         /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    uint32_t in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt, const char *name) 
{
  struct dir_entry e; 
  struct dir *temp;
  struct inode *temp_inode, *parent_inode;
  char parent[3] = "..";

  bool result =  inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);

  if (sector != 1) {
    parent_inode = thread_current()->curr_dir ->inode;
    disk_sector_t parent_sec = inode_get_inumber(parent_inode);
    dir_add (thread_current()->curr_dir, name, sector);
    temp_inode = inode_open(sector);
    temp = dir_open(temp_inode);
    dir_add (temp, parent, parent_sec);
    dir_close(temp);
  }

  return result;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if ((e.in_use==1) && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;
  char *token, *save_ptr, *name_copy;
  struct dir *temp_dir;
  int i;
  bool has_delimiter = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (*name == NULL) {
    *inode = thread_current()->curr_dir->inode;
    return true;
  }

  temp_dir = dir;

  for (i=0; i<strlen(name); i++) {
    if (*(name+i)=='/') {
      has_delimiter = true;
      break;
    }
  }

  if (has_delimiter) {
    name_copy = (char *)malloc(strlen(name)+1);
    memset(name_copy, 0, strlen(name)+1);
    memcpy(name_copy, name, strlen(name));

    for (token = strtok_r (name_copy, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)) {
      if (!strcmp(token, "."))
        continue;
      
      if (lookup (temp_dir, token, &e, NULL)) {
        *inode = inode_open (e.inode_sector);
        temp_dir = dir_open(*inode);
      }
      else {
        *inode = NULL;
        free(name_copy);
        return false;
      }
    }
    free(name_copy);
  } else {
    if (!strcmp(name, ".")) {
      *inode = inode_open (inode_get_inumber(dir->inode));
    }
    else {
      if (lookup (dir, name, &e, NULL)) 
        *inode = inode_open (e.inode_sector);
      else
        *inode = NULL;
      return *inode!=NULL;
    }
  }

  return true;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) 
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use==0)
      break;

  /* Write slot. */
  e.in_use = 1;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir *dir_parent = NULL;
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;
  char readdir_name[NAME_MAX + 1];

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  // For dir-rm-parent testcase
  if (inode_get_isdir (inode)) {
    dir_parent = dir_open(inode);
    if (dir_readdir(dir_parent, readdir_name)) {
      goto done;
    }
  }

  /* Erase directory entry. */
  e.in_use = 0;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (strcmp(e.name, "..")) {
        if (e.in_use == 1)
          {
            strlcpy (name, e.name, NAME_MAX + 1);
            return true;
          } 
      }
    }
  return false;
}


void parse_path (char *full_name, char *path, char *file_name) {
  char *token, *save_ptr, *prev_token, *full_name_copy;
  size_t file_name_len;
  bool has_delimiter = false;
  int i;

  for (i=0; i<strlen(full_name); i++) {
    if (*(full_name+i)=='/') {
      has_delimiter = true;
      break;
    }
  }

  if (has_delimiter) {
    full_name_copy = (char *)malloc(strlen(full_name)+1);
    memset(full_name_copy, 0, strlen(full_name)+1);
    memcpy(full_name_copy, full_name, strlen(full_name));
    memset(path, 0, strlen(full_name)+1);
    
    for (token = strtok_r (full_name_copy, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)) {
      prev_token = token;
    }
    file_name_len = strlen(prev_token);
    memset(file_name, 0, file_name_len+1);
    memcpy(file_name, prev_token, file_name_len);
    memcpy(path, full_name, strlen(full_name)-file_name_len-1);
  }
  else {
    path = NULL;
    memcpy(file_name, full_name, strlen(full_name)+1);
  }
}
