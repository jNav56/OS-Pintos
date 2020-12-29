#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Juan Driving
* Look for the file with file descriptor fd in the thread's
* list of open files */
// static struct open_file *
// get_file (int fd)
// {
//   struct thread *cur = thread_current ();
  
//   /* Iterating list element for file struct and last file list element */
//   struct list_elem *iterate = list_begin(&cur->file_list);
//   struct list_elem *end = list_end(&cur->file_list);

//   /* Traverse through thread's list of file */
//   while(iterate != end) {
//     /* Grab file struct and check its file descriptor */
//     struct open_file *cur_file = 
//                       list_entry (iterate, struct open_file, file_elem);
//     if(cur_file->fd == fd) {
//       return cur_file;
//     }
//     iterate = list_next (iterate);
//   }
//   return NULL;
// }

/* Juan Driving
* Iterate through the current list of children to wait for them
* to exit and then exit yourself */
static void
wait_on_children (struct thread *cur) {
  struct thread *child = NULL;

  struct list_elem *iterate = list_begin (&cur->children);
  struct list_elem *end = list_end (&cur->children);

  while(iterate != end) {

    child = list_entry (iterate, struct thread, child_elem);
    //sema_down (&child->sema_wait);
    sema_up (&child->sema_exit);

    iterate = list_next(iterate);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread *new_child;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  /* If a thread could not be created, then free memory and return error */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  /* Keegan Driving
  * Creating a child was successful and now we retrieve the thread 
  * to add it to the list of the thread's children list*/
  new_child = get_thread (tid);
  list_push_back (&thread_current ()->children, &new_child->child_elem);

  /* Juan Driving
  * Wait and see if the child was successful in being loaded in */
  sema_down (&new_child->sema_load);
  if(!new_child->load_success){
    list_remove (&new_child->child_elem);
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current ();

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit and sema up to continue in process execute*/
  palloc_free_page (file_name);
  if (!success) {
    sema_up (&cur->sema_load);
    thread_exit ();
  }

  /* Juan Driving
  * If load was successful, then indicate that in the thread member
  * and sema up on loading semaphore to continue in process execute */
  cur->load_success = 1;
  sema_up (&cur->sema_load);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  int exit_status, found = 0;
  struct thread *cur = thread_current ();
  struct thread *child;

  struct list_elem *iterate = list_begin (&cur->children);
  struct list_elem *end = list_end (&cur->children);

  /* Juan Driving
  * Iterate through all the children of the current thread and
  * find the child who we have to wait on */
  while(!found && iterate != end) {
    child = list_entry (iterate, struct thread, child_elem);

    if(child->tid == child_tid) {
      found = 1;
      iterate = list_prev (iterate);
    }
    iterate = list_next (iterate);
  }

  /* If the child did not exist, then return -1 */
  if(iterate == end) {
    return -1;
  }

  /* Keegan Driving
  * Remove child from children list since it will no longer
  * be on the thread's list after it has terminating */
  list_remove (&child->child_elem);

  /* Sema down on the wait semaphore and sema up on exit semaphore
  * to indicate the thread can exit */
  sema_down (&child->sema_wait);
  exit_status = child->exit_status;
  sema_up (&child->sema_exit);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int i = 1;

  /* Keegan Driving
  * Print process termination message */
  printf("%s: exit(%d)\n", cur->command, cur->exit_status);

  /* Check if the lock is being held by the current thread
  * and release it if so since we will not use anymore*/
  if(lock_held_by_current_thread(&file_lock)) {
    lock_release (&file_lock);
  }

  while (++i < 128) {
    if (cur->file_list_array[i]) {

      lock_acquire (&file_lock);
      file_close(cur->file_list_array[i]);
      lock_release (&file_lock);

      cur->file_list_array[i] = NULL;
    }
  }

  // /* Acquire the executable file and close it and afterwards
  // * remove it from the list of files opened by the thread;
  // * start at 2 since 0 and 1 are reserved for the console and
  // * files begin to be added to a thread's list with 2 */
  // struct open_file *cur_file = get_file (2);
  // lock_acquire (&file_lock);
  // file_close (cur_file->file);
  // lock_release (&file_lock);

  // /* Remove the executable file from the list of files opened */
  // list_remove (&cur_file->file_elem);
  // //palloc_free_page (cur_file);
  // free (cur_file);

  /* Juan Driving
  * Sema up to notify a parent that is waiting that this thread has
  * finished excetuting, ensure this thread's children have completed
  * executing, after just wait on parent to reap the thread */
  sema_up (&cur->sema_wait);
  wait_on_children (cur);
  sema_down (&cur->sema_exit);

  palloc_free_page (cur->command);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;

  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i, fd = 2;
  char *token, *save_ptr, *copy;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Keegan Driving
  * Make a copy of the user input and extract the first string */
  copy = palloc_get_page (0);
  if (copy == NULL)
    return TID_ERROR;
  strlcpy (copy, file_name, PGSIZE);
  token = strtok_r (copy, " ", &save_ptr);

  /* Save the token to the command and open the file */
  t->command = palloc_get_page (0);
  strlcpy(t->command, token, strlen(token) + 1);
  file = filesys_open (token);
  if (file == NULL) {
    printf ("load: %s: open failed\n", file_name);
    goto done; 
  }

  /* Allocate memory for the file to be opened */
  // struct open_file *new_file = (struct open_file *) 
  //                              malloc(sizeof(struct open_file));
  // if(new_file == NULL) {
  //   return false;
  // }

  /* Fill in the members of the new file created and put it in
  * the thread's file list */
  // new_file->fd = t->next_fd++;
  // new_file->file = file;
  // list_push_back(&t->file_list, &new_file->file_elem);

  while (t->file_list_array[fd] && fd < 128) {
    fd++;
  }
  t->file_list_array[fd] = file;

  /* Juan Driving
  * After we have confirmed that file is not NULL, we must
  * prevent any writing from happeing until allowed */
  lock_acquire (&file_lock);
  file_deny_write (file);
  lock_release (&file_lock);

  lock_acquire (&file_lock);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release (&file_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  lock_release (&file_lock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&file_lock);
      if (file_ofs < 0 || file_ofs > file_length (file)) {
        lock_release (&file_lock);
        goto done;
      }
      lock_release (&file_lock);

      lock_acquire (&file_lock);
      file_seek (file, file_ofs);
      lock_release (&file_lock);

      lock_acquire (&file_lock);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) {
        lock_release (&file_lock);
        goto done;
      }
      lock_release (&file_lock);

      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  //file_close(file);

  palloc_free_page(copy);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 
  
  lock_acquire (&file_lock);

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) {
    lock_release (&file_lock);
    return false;
  }
  lock_release (&file_lock);

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  lock_acquire (&file_lock);
  file_seek (file, ofs);
  lock_release (&file_lock);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      lock_acquire (&file_lock);

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          lock_release (&file_lock);
          return false; 
        }
      lock_release (&file_lock);

      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *file_name) 
{
  uint8_t *kpage;
  bool success = false;
  char *token, *save_ptr, *copy;
  char **arguments;
  int num_bytes = 0, index = 0, i;

  /* Juan Driving
  * Continue if arguments, the array of strings, can be allocated memory */
  arguments = palloc_get_page(0); 
  if (arguments == NULL) {
  	return TID_ERROR; 
  }

  /* Continue if a copy for the user arguments can be allocated memory */
  copy = palloc_get_page (0);
  if (copy == NULL) {
    return TID_ERROR;
  }
  strlcpy (copy, file_name, PGSIZE);

  /* Iterate through the user arguments and save each string into arguments */
  token = strtok_r (copy, " ", &save_ptr);
  while(token != NULL) {
    arguments[index] = token;
    index++;
    token = strtok_r (NULL, " ", &save_ptr);
  }

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;

        /* Keegan Driving
        * A char pointer to increase stack from PHYS_BASE */
        char *my_esp = (char *)*esp;

        /* push arguments onto the stack from right to left */
        index--;
        int argument_length;
        for (i = index; i >= 0; i--) {
          argument_length = strlen(arguments[i]) + 1;
          
          num_bytes += argument_length;
          my_esp -= argument_length;

          strlcpy(my_esp, arguments[i], argument_length);
          arguments[i] = my_esp;
        }

        /* Section for word alignment based on number of bytes all of the
        * strings make up together */
        while (num_bytes % 4 != 0) {
        	my_esp--;
        	*my_esp = 0; 
        	num_bytes++;
        }

        /* Save the zero char pointer to the stack */
        my_esp -= 4;
        *my_esp = 0;

        /* Juan Driving
        * Save each argument pointer to the stack */
        for (i = index; i >= 0; i--) {
          my_esp -= 4;
          *((int *)my_esp) = (unsigned)arguments[i];
        }

        /* Save the pointer to the atring array to the stack */
        void *tmp = my_esp;
        my_esp -= 4;
        *((int *)my_esp) = (unsigned)tmp;

        /* Save the number of arguments to the stack */
        my_esp -= 4;
        *my_esp = index + 1;

        /* Save the return address zero to the stack */
        my_esp -= 4;
        *my_esp = 0;
        
        *esp = my_esp;
      } else {
        palloc_free_page (kpage);
      }
    }

  /* hex_dump(*esp, *esp, PHYS_BASE - *esp, true); */

  /* Free up memory used for copy and arguments */
  palloc_free_page (copy);
  palloc_free_page (arguments);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
