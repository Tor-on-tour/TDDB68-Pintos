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
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) //1
{
  char *fn_copy;
  tid_t tid;
  struct dogtag * dogtag = malloc(sizeof(struct dogtag));
  PRINT("Process_execute \n#######################\n\n");

  //struct child* child = malloc(sizeof(struct child));
  sema_init(&dogtag->wait_sema,0);
  sema_init(&dogtag->load_sema,0);
  lock_init(&dogtag->thread_lock);
  //child->dogtag_ptr = dogtag; //point child to dogtag
  dogtag->cleaning_duty = 2;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL){
    return TID_ERROR;
    }
  strlcpy (fn_copy, file_name, PGSIZE);
  //assign information to the childs dogtag
  dogtag->filename = fn_copy;

  int n = strcspn(file_name, " ");
  char *filename[n];
  strlcpy(filename,file_name, n+1);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(filename, PRI_DEFAULT, start_process, dogtag);
  dogtag->tid = tid;
  PRINT("Process_execute: tid: %d \n\n", tid);
  PRINT("Process_execute: dog_tid: %d \n\n", dogtag->tid);
  PRINT("Process_execute: load_sema Downed\n\n");

  sema_down(&dogtag->load_sema); //constrain parent
  PRINT("Process_execute: load_sema Uped\n\n");
  if (tid == TID_ERROR){
    PRINT("Process_execute: GOT TID_ERROR \n\n");
    palloc_free_page (fn_copy); //no exit status because not even created?
  }
  if(dogtag->running == 0){
    PRINT("Process_execute: kid not running !!!: %d \n\n", tid);
    dogtag->tid = TID_ERROR;
    tid = TID_ERROR;
  }
  else
  {
    //lock_acquire(&dogtag->thread_lock);
    PRINT("Process_execute: pushing kid in list\n\n\n");
    list_push_back(&thread_current()->children, &dogtag->elem);
    //lock_release(&dogtag->thread_lock);
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *dogtag_) //2
{

PRINT("start_process \n#####################\n\n");
  struct dogtag *dogtag = dogtag_;
  struct intr_frame if_;
  bool success;
  char *filename = dogtag->filename;
  PRINT("start_process dogtag->filename : %s \n\n", dogtag->filename);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(filename, &if_.eip, &if_.esp);

  if(success){
  //lock_acquire(&dogtag->thread_lock);s
  dogtag->running = 1;
  PRINT("start process load = SUCCESS \n\n");
  thread_current()->dogtag_ptr = dogtag;
  //lock_release(&dogtag->thread_lock);
  }
  //**
  palloc_free_page (filename);
  /* If load failed, quit. */
  if (!success){
    PRINT("start process load = FAIL \n\n");
    lock_acquire(&dogtag->thread_lock);
    dogtag->cleaning_duty = 1;
    dogtag->exit_status = -1;
    lock_release(&dogtag->thread_lock);
    sema_up(&dogtag->load_sema);
    PRINT("Start process !sucess wait_sema Uped\n\n");
    thread_exit ();
  }

  sema_up(&dogtag->load_sema);
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
process_wait (tid_t child_tid UNUSED) //torsdag
{
  PRINT("process_wait\n###################\n\n");
  int exit_status;
  struct list_elem *e = list_begin(&thread_current()->children);

  while(e !=list_end(&(thread_current()->children))){
    PRINT("process_wait 2\n\n");
    struct dogtag *kids_dogtag = list_entry(e, struct dogtag, elem);
    e = list_next(e);
    PRINT("process_wait childtid : %d \n\n", child_tid);
    PRINT("process_wait kids_dogtag->tid : %d \n\n", kids_dogtag->tid);
    if(kids_dogtag->tid == child_tid)                // Loop over children to find matching tid
    {
      lock_acquire(&kids_dogtag->thread_lock);
      PRINT("process_wait 3\n\n");
      PRINT("Process wait kids_dogtag->cleaning_duty:  %d \n\n", kids_dogtag->cleaning_duty);
      if(kids_dogtag->cleaning_duty == 2)
      {
        PRINT("process_wait 4\n\n");
        PRINT("process_wait: wait_sema Downed\n\n");
        sema_down(&(kids_dogtag->wait_sema)); ////let child play, wait for child with help of sema
        PRINT("process_wait: wait_sema Uped\n\n");
        exit_status = kids_dogtag->exit_status;
        PRINT("process_wait All alive but kid dies with status %d\n\n", exit_status);
        kids_dogtag->cleaning_duty -= 1;
        lock_release(&kids_dogtag->thread_lock);
        //lock_release(&kids_dogtag->thread_lock);
        return exit_status;
      }
      else
      {
      /////////////////////////////////////////////////////////////  PRINT(" process_wait 5\n\n\n");
        lock_release(&kids_dogtag->thread_lock);
        exit_status = kids_dogtag->exit_status;
        PRINT("Child with status %d is dead\n\n", exit_status);
        list_remove(list_prev(e));
        free(kids_dogtag);                   //child is dead, clean up mess
        //lock_release(&kids_dogtag->thread_lock);
        return exit_status;
      }
      //lock_release(&kids_dogtag->thread_lock);
    }
  PRINT("process_wait 6\n\n");
  }
  PRINT("process_wait 7\n\n");
  //lock_release(&thread_current()->thread_lock);// no tid found
  //lock_release(&thread_current()->dogtag_ptr->thread_lock);
  return -1;
}
//
// timer_interrupt (struct intr_frame *args UNUSED)
// {
//   thread_tick ();
//   ++ticks;
//   struct list_elem *e;
//   enum intr_level old_level;
//   old_level = intr_disable ();
//   for(e = list_begin(&sleeping_list); e != list_end(&sleeping_list); e = list_next(e))
//     {
//       struct thread *currThread = list_entry(e, struct thread, sleep_elem);
//       if(currThread->timer <= timer_ticks()){
//
//         sema_up(&currThread->sema_sleep);
//         list_remove(e);
//       }
//     }
//     intr_set_level(old_level);
//   }

/* Free the current process's resources. */
void
process_exit (void)
{
  PRINT("process_exit \n###################\n\n");
  struct thread *cur = thread_current();
  uint32_t *pd;
  //sema_down(&cur->dogtag_ptr->sema);

  //if(cur->tid != 1)  //1 for the initial process
  //{
                      // Loop over children to find matching tid
      PRINT("process_exit1 \n\n");
      struct list_elem *e = list_begin(&(thread_current()->children));
      PRINT("process_exit List length: %d \n\n", list_size(&(thread_current()->children)));
      while(e!=list_end(&(thread_current()->children))){
        PRINT("process_exit2 \n\n");              // gather kids
         struct dogtag* kids_dogtag = list_entry(e, struct dogtag, elem);
         e=list_next(e);
         PRINT("process_exit kids_dogtag->cleaning_duty  %d \n\n", kids_dogtag->cleaning_duty);
         lock_acquire(&kids_dogtag->thread_lock);                                   // Maste mojligt ligga i thread och inte dogtag

         if(kids_dogtag->cleaning_duty < 2){
           //list_remove(list_prev(e));
           lock_release(&kids_dogtag->thread_lock);                             // if any of the kids are dead
           free(kids_dogtag);
                                                           // clean up the childs dogtag
         }
         else{
           kids_dogtag->cleaning_duty--;
           PRINT("process_exit4 \n\n");                 // tell the kids its time for you to move on
           sema_up(&kids_dogtag->wait_sema);
           list_remove(list_prev(e));
           lock_release(&kids_dogtag->thread_lock);
         }

       }
       if(cur->dogtag_ptr != NULL)
       if(cur->dogtag_ptr->cleaning_duty == 1){
         PRINT("process_exit5 \n\n");
         PRINT("process_exit cur->dogtag_ptr->cleaning_duty  %d \n\n\n", cur->dogtag_ptr->cleaning_duty);                        //look if parent is dead
         free(cur->dogtag_ptr);
       }
       else{
      PRINT("process_exit6 \n\n");
      sema_up(&cur->dogtag_ptr->wait_sema); ////
      cur->dogtag_ptr->cleaning_duty--; //onsdag kvall
     }

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

static bool setup_stack (void **esp);
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
  int i;

  //filename = strtok_r(filename," ", char **save_ptr)

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Set up stack. */
  if (!setup_stack (esp)){
    goto done;
  }

  char *token;
  char *save_ptr;
  int argc = 0;
  int counter = 0;
  char ** argv = malloc(32*sizeof(char*));
  //printf("\n\n load filename: %s\n\n:", file_name);
  for(token = strtok_r(file_name, " ", &save_ptr);
   token != NULL;
   token = strtok_r(NULL, " ", &save_ptr))
  {
    *esp -= strlen(token) + 1; // +1 for /0
    argv[counter] = *esp;
    counter++;
    memcpy(*esp, token, strlen(token)+1);
  }
  argv[counter] = 0;
  *esp -= (uint32_t)(*esp) % 4; // align with word-format in stack
  //*esp -= 4;
  //**((char**)esp) = NULL; //set NULL after alignment

  char **stack = (char **)(*esp);
  stack--;
  *stack = 0;
  stack--;
//
  argc = counter;
  for(;counter >= 0;counter--)
{
  *esp -= sizeof(char*);
  //printf("\n\n Counter argv: %s\n\n:", argv[counter]);
  memcpy(*esp,&argv[counter],sizeof(char*));
}
  //argv
  token = *esp;
  *esp -= sizeof(char**);
  memcpy(*esp, &token,sizeof(char**));
  //argc
  *esp -= sizeof(int);
  memcpy(*esp,&argc,sizeof(int));
  //return
  *esp -= sizeof(void*);
  void* blob;
  memcpy(*esp,&blob,sizeof(void));
  //**((char**)esp) = NULL;

  //free(argv);

   /* Uncomment the following line to print some debug
     information. This will be useful when you debug the program
     stack.*/
//#define STACK_DEBUG

#ifdef STACK_DEBUG
  printf("*esp is %p\nstack contents:\n", *esp);
  hex_dump((int)*esp , *esp, PHYS_BASE-*esp+16, true);
  /* The same information, only more verbose: */
  /* It prints every byte as if it was a char and every 32-bit aligned
     data as if it was a pointer. */
  void * ptr_save = PHYS_BASE;
  i=-15;
  while(ptr_save - i >= *esp) {
    char *whats_there = (char *)(ptr_save - i);
    // show the address ...
    printf("%x\t", (uint32_t)whats_there);
    // ... printable byte content ...
    if(*whats_there >= 32 && *whats_there < 127)
      printf("%c\t", *whats_there);
    else
      printf(" \t");
    // ... and 32-bit aligned content
    if(i % 4 == 0) {
      uint32_t *wt_uint32 = (uint32_t *)(ptr_save - i);
      printf("%x\t", *wt_uint32);
      printf("\n-------");
      if(i != 0)
        printf("------------------------------------------------");
      else
        printf(" the border between KERNEL SPACE and USER SPACE ");
      printf("-------");
    }
    printf("\n");
    i++;
  }
#endif

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
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

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
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

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

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

  file_seek (file, ofs);
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

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
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
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
        //*esp = PHYS_BASE - 12;
      else
        palloc_free_page (kpage);
    }
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
