#include <stdio.h>
#include <stdbool.h>

#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#include "userprog/syscall.h"
#include "userprog/process.h"

#include "devices/input.h"

#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"


static void syscall_handler (struct intr_frame *);

bool pointer_safe(void *esp) {
  return esp != NULL && is_user_vaddr(esp) && pagedir_get_page(thread_current()->pagedir,esp) != NULL;
}

bool
buffer_safe(void * esp) {
    char * buffer = *(char**) esp;
    if (buffer != NULL && pointer_safe(buffer))
    {
        char * p;

        for (p = buffer; *p != '\0'; p++)
        {
            if (!pointer_safe(p))
                return false;
        }
    }
    else{
        return false;
    }
    return true;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool
create(struct intr_frame *f, const char *file, unsigned initial_size)
{
  if(file == NULL){
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

int
open(const char *file)
{
	// Find empty fd slot
	int fd = 0;
	for(; fd <= FDTABLE_SIZE; fd++)
	{
		if(thread_current()->fdtable[fd] == NULL)
			break;
	}

	if(fd == FDTABLE_SIZE)
		return -1;

	thread_current()->fdtable[fd] = filesys_open(file);

	if(thread_current()->fdtable[fd] == NULL)
		return -1;

	return fd + 2;
}

void
close(int fd)
{
  if(1 < fd && fd < FDTABLE_SIZE && thread_current()->fdtable[fd - 2] != NULL) //Within fd table?
  {
    file_close(thread_current()->fdtable[fd - 2]);
    thread_current()->fdtable[fd - 2] = NULL;
  }
}

int
read(int fd, void *buffer, unsigned size)
{
  if(fd < 0 || fd == 1 || FDTABLE_SIZE <= fd){
    return -1;
  }
  if(fd == STDIN_FILENO){
    unsigned tick = 0;
    for(;tick < size; tick++)
    {
      ((uint8_t*)buffer)[tick] = input_getc();
    }
    return size;
  }
  if(thread_current()->fdtable[fd - 2] == NULL){
    return -1;
  }
  return file_read(thread_current()->fdtable[fd - 2], buffer, size);
}

int
write(int fd, const void *buffer, unsigned size)
{
  if(fd == NULL || fd <= 0 || fd >= FDTABLE_SIZE){
    return -1;
  }
  //printf("fd:%d\n",fd);

  if(fd == STDOUT_FILENO){
    //printf("buffer:%p\n",buffer);
    //check for large buffer problem later
    putbuf(buffer, size);
    return size;
  }
  if(thread_current()->fdtable[fd - 2] == NULL){
    return -1;
  }

  return file_write(thread_current()->fdtable[fd - 2], buffer, size);
}

void
exit(int status)
{
  printf("%s: exit(%d)\n",thread_current()->name, status);
  thread_current()->dogtag_ptr->exit_status = status;
	thread_exit();
}
//lab3
int
wait(int pid)
{
  return process_wait(pid);
}

int
exec(const char *cmd_line)
{
  //printf("cmd_line!: (%s)\n", cmd_line);
  return process_execute(cmd_line);
}


/////////////////////////////////////////////////
static void
syscall_handler (struct intr_frame *f UNUSED)
{

  int *syscall = f -> esp; //

  if(!is_user_vaddr(syscall)){
    exit(-1);
  }
  if(pagedir_get_page(thread_current()->pagedir, syscall) == NULL){
  	exit(-1);
  }
  if(!pointer_safe(f->esp)){
    exit(-1);
  }
  switch(*syscall){

    case SYS_CREATE:
		{
			if(!is_user_vaddr(syscall[1]) || !is_user_vaddr(syscall[2])){
				exit(-1); //
        }
			if(pagedir_get_page(thread_current()->pagedir, syscall[1]) == NULL){
				exit(-1);
        }

			const char *file = (const char*)syscall[1];
			unsigned initial_size = (unsigned)syscall[2];

      if(buffer_safe(&file)){
			f->eax = create(f, file, initial_size);
      }
			break;
		}

    case SYS_OPEN:
      {

  			const char *file = (const char*)syscall[1];

        if(!buffer_safe(&file)){
          exit(-1);
          break;
        }

  			f->eax = open(file);
  			break;
  		}
    case SYS_CLOSE:
  {
    int fd = (int)syscall[1];

    //if(!pointer_safe(&fd))
    //    exit(-1);
    close(fd);
    f->eax = 0;
    break;
    }

    case SYS_READ:
  {
    if(!is_user_vaddr(syscall[1]) || !is_user_vaddr(syscall[2]) || !is_user_vaddr(syscall[3]))
      exit(-1);
    if(pagedir_get_page(thread_current()->pagedir, syscall[2]) == NULL)
      exit(-1);

    int fd = (int)syscall[1];
    void *buffer = (void*)syscall[2];
    unsigned size = (unsigned)syscall[3];
    if(!buffer_safe(&buffer)){
      exit(-1);
      break;
    }

    f->eax = read(fd, buffer, size);
    break;
  }

    case SYS_WRITE:
    {
      // if(!is_user_vaddr(syscall[1]) || !is_user_vaddr(syscall[2]) || !is_user_vaddr(syscall[3]))
      // exit(-1);
      if(pagedir_get_page(thread_current()->pagedir, syscall[2]) == NULL)
      exit(-1);


      //printf ("system call! WRITE\n");
      int fd = (int)syscall[1];
      void *buffer = (void*)syscall[2];
      unsigned size = (unsigned)syscall[3];
      if(buffer_safe(&buffer)){
        f->eax = write(fd,buffer,size);
      }
      break;
    }

    case SYS_HALT:
    {
      //printf ("system call! HALT\n");
      power_off();
      break;
    }

    case SYS_EXIT:
    {
			if(!is_user_vaddr(syscall[1])){
				exit(-1);
      }
			int status = (int)syscall[1];
			exit(status);
			break;
		}

    case SYS_WAIT:
    {
      if(!is_user_vaddr(syscall[1])){
        exit(-1);
      }
      const int pid = (int)syscall[1];
      f->eax = wait(pid);
      break;
    }

    case SYS_EXEC:
    {

      const char *cmd_line = (const char*)syscall[1];
      if(!buffer_safe(&cmd_line)){
        exit(-1);
      }
      else{
      f->eax = exec(cmd_line);
      break;
    }
    }

  }
}
