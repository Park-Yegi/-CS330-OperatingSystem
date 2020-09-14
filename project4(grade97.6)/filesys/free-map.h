#ifndef FILESYS_FREE_MAP_H
#define FILESYS_FREE_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/disk.h"

void free_map_init (void);
void free_map_read (void);
void free_map_create (void);
void free_map_open (void);
void free_map_close (void);

bool free_map_allocate (size_t, disk_sector_t *);
void free_map_release (disk_sector_t, size_t);
// bool free_map_allocate_index (size_t cnt, disk_sector_t *direct, disk_sector_t *indirect, disk_sector_t *doubly_indirect, disk_sector_t *indirect_arr, disk_sector_t *parent_arr, disk_sector_t **doubly_arr);
bool free_map_allocate_index (size_t start, size_t cnt, disk_sector_t *direct, disk_sector_t *indirect, disk_sector_t *doubly_indirect, disk_sector_t *indirect_arr, disk_sector_t *parent_arr, disk_sector_t **doubly_arr);

#endif /* filesys/free-map.h */
