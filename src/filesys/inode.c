#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static void allocate_direct(struct inode_disk *inode_disk,
                              block_sector_t sectors);
static void allocate_indirect(struct inode_disk *inode_disk,
                              block_sector_t sectors);
static void allocate_doubly_indirect(struct inode_disk *inode_disk,
                              block_sector_t sectors);
static void increase_inode_length (struct inode *inode, off_t total_bytes);

/* Array to serve indirect allocation */
struct index_block
{
  block_sector_t indirect_arr[INDIRECT_ENTRIES];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
/* Keegan Driving */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  struct index_block *temp_array = NULL;
  block_sector_t sector = -1, index;
  pos /= BLOCK_SECTOR_SIZE;

  if (pos > TOTAL_ENTRIES) {
    PANIC ("Position is out of bounds");
  }

  /* pos is within direct entries */
  if (pos < DIRECT_ENTRIES) {
    sector = inode->data.direct_blocks[pos];

  /* pos is within first indirection */
  } else if (pos - DIRECT_ENTRIES < INDIRECT_ENTRIES) {
    pos -= DIRECT_ENTRIES;

    /* Get array of entries from first indirection to get sector */
    temp_array = malloc (sizeof (struct index_block));
    block_read(fs_device, inode->data.indirect_index[0], temp_array);
    sector = temp_array->indirect_arr[pos];
  
  /* pos is within second indirection */
  } else {
    pos = pos - DIRECT_ENTRIES - INDIRECT_ENTRIES;

    /* Get array of array of entries from second indirection */
    temp_array = malloc (sizeof (struct index_block));
    block_read(fs_device, inode->data.indirect_index[1], temp_array);

    /* Get index in temp_array that holds sector */
    index = temp_array->indirect_arr[pos / INDIRECT_ENTRIES];

    /* Reassign temp_array the address to new array of second indirection */
    block_read(fs_device, index, temp_array);
    sector = temp_array->indirect_arr[pos % INDIRECT_ENTRIES];
  }

  if (!temp_array) {
    free (temp_array);
  }

  return sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false, temp;
  int num_sectors, index = -1;
  block_sector_t *sector_pointer; 

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      /* Juan Driving */
      /* Initilize directory data */
      disk_inode->is_directory = dir;
      disk_inode->parent_dir = 1;
      disk_inode->length = length;

      /* Initialize sector content */
      while (++index < DIRECT_ENTRIES) {
        disk_inode->direct_blocks[index] = -1;
      }
      free_map_allocate (1, sector_pointer);
      disk_inode->direct_blocks[0] = *sector_pointer;

      disk_inode->indirect_index[0] = -1;
      disk_inode->indirect_index[1] = -1;

      /* Get the number of sectors needed */
      num_sectors = DIV_ROUND_UP (length, BLOCK_SECTOR_SIZE);

      if (num_sectors > TOTAL_ENTRIES) {
        PANIC("Disk Space too small");
      }

      /* Allocate to direct entries */
      temp = num_sectors <= DIRECT_ENTRIES;
      allocate_direct(disk_inode, temp ? num_sectors : DIRECT_ENTRIES);
      num_sectors -= DIRECT_ENTRIES;

      /* If still need to allocate, go to first indirection */
      if (num_sectors > 0) {

        temp = num_sectors <= INDIRECT_ENTRIES;
        allocate_indirect(disk_inode, temp ? num_sectors : INDIRECT_ENTRIES);
        num_sectors -= INDIRECT_ENTRIES;

        /* Go to second indirection */
        if (num_sectors > 0) {
          allocate_doubly_indirect(disk_inode, num_sectors);
        }
      }

      /* Write reference to disk_inode */
      block_write (fs_device, sector, disk_inode);
      success = true;
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
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
  block_read (fs_device, inode->sector, &inode->data);
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
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  int i = -1;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Write to disk */
      block_write(fs_device, inode->sector, &inode->data);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Keegan Driving */
          free_map_release (inode->sector, 1);
          while (inode->data.direct_blocks[++i] != -1) {
            free_map_release (inode->data.direct_blocks[i], 1);
          }
          
        }

      free (inode); 
    }
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
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector(inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

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

  /* Increase inode lenght if size and offset overwhelm current length */
  if (inode->data.length < offset + size) {
    increase_inode_length(inode, size + offset);
  }

  /* Have to make sure we can write */
  if (inode->deny_write_cnt) {
    return 0;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector(inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

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

/* Juan Driving */
/* Allocate sectors for num_sectors entries in the inode_disk */
static void
allocate_direct(struct inode_disk *inode_disk, block_sector_t num_sectors)
{
  int i = -1;

  while (++i < num_sectors) {
    if (inode_disk->direct_blocks[i] == -1) {
      free_map_allocate(1, &inode_disk->direct_blocks[i]);
    }
  }
}

/* Keegan Driving */
/* Allocate array of sectors for a first indirection */
static void
allocate_indirect(struct inode_disk *inode_disk, block_sector_t sectors)
{
  int i = -1;
  struct index_block *indirect = calloc (1, sizeof *indirect);

  /* Check if second indirect reference is full, otherwise allocate space */
  if (inode_disk->indirect_index[0] != -1) {
    block_read(fs_device, inode_disk->indirect_index[0], indirect);
  } else {
    free_map_allocate(1, &inode_disk->indirect_index[0]);
  }

  /* Go through sectos of indirect to allocate if possible */
  while (++i < sectors) {
    if(!(indirect->indirect_arr[i])) {
      free_map_allocate(1, &indirect->indirect_arr[i]);
    }
  }

  block_write(fs_device, inode_disk->indirect_index[0], indirect);
  free(indirect);
}

/* Juan Driving */
/* Allocate an array of array of sectors for a second indirection */
static void
allocate_doubly_indirect(struct inode_disk *inode_disk, block_sector_t sectors)
{
  int i = -1, j = -1, required, allocate;
  struct index_block *dub_indirect = calloc (1, sizeof *dub_indirect);

  /* Check if second indirect reference is full, otherwise allocate space */
  if (inode_disk->indirect_index[1] != -1) {
    block_read(fs_device, inode_disk->indirect_index[1], dub_indirect);
  } else {
    free_map_allocate(1, &inode_disk->indirect_index[1]);
  }

  /* Get the required number of sectors to allocate, and do it */
  required = DIV_ROUND_UP(sectors, INDIRECT_ENTRIES);
  while (++i < required) {

    /* If possible allocate array, otherwise skip */
    if (dub_indirect->indirect_arr[i] == NULL) {
      free_map_allocate(1, &dub_indirect->indirect_arr[i]);
      struct index_block *indirect = calloc (1, sizeof *indirect);

      /* Allocate indirect to the fullest unless in the last array */
      allocate = i + 1 == required ? sectors % INDIRECT_ENTRIES :
                                      INDIRECT_ENTRIES;

      /* Go through sectos of indirect to allocate if possible */
      while (++j < allocate) {
        free_map_allocate(1, &indirect->indirect_arr[j]);
      }
      
      block_write(fs_device, dub_indirect->indirect_arr[i], indirect);
      free(indirect);
    }
    j = -1;
  }

  block_write(fs_device, inode_disk->indirect_index[1], dub_indirect);
  free(dub_indirect);
}

/* Keegan Driving */
/* Increase the length of the given inode */
static void
increase_inode_length (struct inode *inode, off_t total_bytes)
{
  int length, remaining_sector, num_sectors;
  off_t bytes_need, sect_need;
  bool temp;

  /* Use this to find out how many sectors we have left currently */
  length = inode->data.length;
  remaining_sector = BLOCK_SECTOR_SIZE - length;

  /* Get the bytes we will need to write and from there find the number
  * of sectors you will need */
  bytes_need = total_bytes - length - remaining_sector;
  sect_need = bytes_need > 0 ? DIV_ROUND_UP (bytes_need, BLOCK_SECTOR_SIZE) :0;

  /* Get the updated length of the inode */
  num_sectors = DIV_ROUND_UP (length, BLOCK_SECTOR_SIZE) + sect_need + 1;

  /* Exit if allocation not possible */
  if (num_sectors > TOTAL_ENTRIES) {
    PANIC("Disk Space too small");
  }

  /* Allocate to direct entries */
  temp = num_sectors <= DIRECT_ENTRIES;
  allocate_direct(&inode->data, temp ? num_sectors : DIRECT_ENTRIES);
  num_sectors -= DIRECT_ENTRIES;

  /* If still need to allocate, go to first indirection */
  if (num_sectors > 0) {

    temp = num_sectors <= INDIRECT_ENTRIES;
    allocate_indirect(&inode->data, temp ? num_sectors : INDIRECT_ENTRIES);
    num_sectors -= INDIRECT_ENTRIES;

    /* Go to second indirection */
    if (num_sectors > 0) {
      allocate_doubly_indirect(&inode->data, num_sectors);
    }
  }

  /* Update length of inode */
  inode->data.length += bytes_need + remaining_sector;
}
