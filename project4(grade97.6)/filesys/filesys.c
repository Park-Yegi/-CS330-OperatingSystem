#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  disk_sector_t inode_sector = 0;
  struct dir *dir; 
  struct inode *d_inode;
  char *path, *file_name, *full_name;

  full_name = (char*)malloc(strlen(name)+1);
  memset(full_name, 0, strlen(name)+1);
  memcpy(full_name, name, strlen(name));
  path = (char*)malloc(strlen(name)+1);
  memset(path, 0, strlen(name)+1);
  file_name = (char*)malloc(14);
  memset(file_name, 0, 14);

  parse_path(full_name, path, file_name);

  if (thread_current()->curr_dir == NULL ) {
    dir = dir_open_root();
  }
  else {
    if (inode_get_isremoved(dir_get_inode(thread_current()->curr_dir)))
      return NULL;

    if (!strncmp(name, "/", 1))
      dir_lookup(dir_open_root(), path, &d_inode);
    else
      dir_lookup(thread_current()->curr_dir, path, &d_inode);
    dir = dir_open(d_inode);
  }

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, file_name, inode_sector));
      
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  free(full_name);
  free(path);
  free(file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir, *parent_dir;
  struct inode *d_inode, *parent_inode;
  char *path, *file_name, *full_name;
  struct inode *inode = NULL;
  char parent[3] = "..";

  full_name = (char*)malloc(strlen(name)+1);
  memset(full_name, 0, strlen(name)+1);
  memcpy(full_name, name, strlen(name));
  path = (char*)malloc(strlen(name)+1);
  memset(path, 0, strlen(name)+1);
  file_name = (char*)malloc(14);
  memset(file_name, 0, 14);

  parse_path(full_name, path, file_name);

  if (thread_current()->curr_dir == NULL) {
    dir = dir_open_root();
  }
  else {
    if (inode_get_isremoved(dir_get_inode(thread_current()->curr_dir)))
      return NULL;

    if (*path == NULL) {
      if (!strncmp(name, "/", 1))
        dir = dir_open_root();
      else
        dir = thread_current()->curr_dir;
    }
    else {
      if (!strncmp(name, "/", 1)) {
        if (!strncmp(name+1, "/", 1))
          dir_lookup(dir_open_root(), path+1, &d_inode);
        else
          dir_lookup(dir_open_root(), path, &d_inode);
      }
      else {
        dir_lookup(thread_current()->curr_dir, path, &d_inode);
      }
      dir = dir_open(d_inode);
    }
  }

  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);

  free(full_name);
  free(path);
  free(file_name);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir;
  struct inode *d_inode;
  char *path, *file_name, *full_name;

  full_name = (char*)malloc(strlen(name)+1);
  memset(full_name, 0, strlen(name)+1);
  memcpy(full_name, name, strlen(name));
  path = (char*)malloc(strlen(name)+1);
  memset(path, 0, strlen(name)+1);
  file_name = (char*)malloc(14);
  memset(file_name, 0, 14);

  parse_path(full_name, path, file_name);

  if (thread_current()->curr_dir == NULL) {
    dir = dir_open_root();
  }
  else {
    if (*path == NULL) {
      if (!strncmp(name, "/", 1))
        dir = dir_open_root();
      else
        dir = thread_current()->curr_dir;
    }
    else {
      if (!strncmp(name, "/", 1))
        dir_lookup(dir_open_root(), path, &d_inode);
      else
        dir_lookup(thread_current()->curr_dir, path, &d_inode);
      dir = dir_open(d_inode);
    }
  }


  bool success = dir != NULL && dir_remove (dir, file_name);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, "root"))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
