#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);

//lab1
bool create(struct intr_frame *f, const char *file, unsigned initial_size);
int open(const char *file);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
int exec(const char *cmd_line);
int wait(int pid);
void exit(int status);
void seek(int fd, unsigned position);
unsigned tell(int fd);
int filesize(int fd);
bool remove(const char *file_name);

//lab3
bool pointer_safe(void *esp);
bool buffer_safe(void * esp);

#endif /* userprog/syscall.h */
