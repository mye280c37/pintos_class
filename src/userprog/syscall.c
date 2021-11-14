#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/synch.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
// 1: halt, exit, exec, wait, read, write - 20192058
static void check_memory_access(void *esp, struct thread *t, int c);
static void halt (void);
static pid_t exec (const char *file);
static int wait (pid_t pid);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);

int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

// 2: create, remove, open, close, filesize, read(file), write(file), seek, tell - 20190258
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static void seek (int fd, unsigned position); 
static unsigned tell (int fd);
static void close (int fd);

static struct lock file_lock;

static void 
check_memory_access(void *esp, struct thread *t, int c){
  if(c == 0){
    if(!is_user_vaddr(esp)||pagedir_get_page(t->pagedir, esp) == NULL)
	    exit(-1);
  }
  else {
    for(int i=1; i<=c; i++){
      if(!is_user_vaddr((void*)(esp+4*i))||pagedir_get_page(t->pagedir, (void*)(esp+4*i)) == NULL)
	      exit(-1);
    }
  }
}

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *t = thread_current();
  
  check_memory_access(f->esp, t, 0);

  int sys_num = *(int *)(f->esp);
  switch (sys_num){
	  case SYS_HALT: 
	  	halt(); 
		break;
	  case SYS_EXIT:
      check_memory_access(f->esp, t, 1);
      exit(*(uint32_t *)(f->esp+4)); 
      break;
	  case SYS_EXEC:
      check_memory_access(f->esp, t, 1);
      f->eax = exec(*(char**)(f->esp+4));
      break;
	  case SYS_WAIT:
      check_memory_access(f->esp, t, 1);
      f->eax = wait(*(tid_t *)(f->esp+4));
      break;
	  case SYS_CREATE:
      check_memory_access(f->esp, t, 2);
      f->eax = create(*(char**)(f->esp+4), *(unsigned*)(f->esp+8));
      break;
	  case SYS_REMOVE:
      check_memory_access(f->esp, t, 1);
      f->eax = remove(*(char**)(f->esp+4));
      break;
	  case SYS_OPEN:
	  	check_memory_access(f->esp, t, 1);
      f->eax = open(*(char**)(f->esp+4));
      break;
	  case SYS_FILESIZE:
	  	check_memory_access(f->esp, t, 1);
		  f->eax = filesize(*(int*)(f->esp+4));
		  break;
	  case SYS_READ:
	  	check_memory_access(f->esp, t, 3);
      f->eax = read((int)*(uint32_t *)(f->esp+4), *(void**)(f->esp+8), *(unsigned*)(f->esp+12));
		  break;
	  case SYS_WRITE:
	  	check_memory_access(f->esp, t, 3);
		  f->eax = write(*(int*)(f->esp+4), (void *)*(uint32_t *)(f->esp+8), *(unsigned*)(f->esp+12));
		  break;
	  case SYS_SEEK:
	  	check_memory_access(f->esp, t, 2);
		  seek(*(int*)(f->esp+4), *(unsigned*)(f->esp+8));
		  break;
	  case SYS_TELL:
	  	check_memory_access(f->esp, t, 1);
		  f->eax = tell(*(int*)(f->esp+4));
		  break;
	  case SYS_CLOSE:
	  	check_memory_access(f->esp, t, 1);
      close(*(int*)(f->esp+4));
		  break;
	  case SYS_FIBONACCI:
	  	check_memory_access(f->esp, t, 1);
      f->eax = fibonacci(*(int *)(f->esp+4));
      break;
	  case SYS_MAX_OF_FOUR_INT:
	  	check_memory_access(f->esp, t, 4);
      f->eax = max_of_four_int(*(int *)(f->esp+4), *(int *)(f->esp+8), *(int *)(f->esp+12), *(int *)(f->esp+16));
      break;
	  default :
      exit(-1);
  }
}

static void 
halt (void)
{
  shutdown_power_off();
}

void 
exit (int status)
{
  int i;
  struct thread *t = thread_current(), *child;
  struct list_elem *e = list_begin(&(t->children));
  for(i=3; i<BUF_MAX; i++){
    if(t->fd_table[i] != NULL){
      close(i);
    }
  }
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);

  thread_exit();
}

static pid_t 
exec (const char *file)
{
  struct thread *t = thread_current();
  if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
      exit(-1);
  return process_execute(file);
}

static int 
wait (pid_t pid)
{
  return process_wait((tid_t)pid);
}

static int 
read (int fd, void *buffer, unsigned size)
{
    int i;
    int ret = 0;
    struct thread *t = thread_current();
    if(!is_user_vaddr((char*)buffer) || pagedir_get_page(t->pagedir, (char*)buffer) == NULL)
        exit(-1);
    lock_acquire(&file_lock);
    if(fd == 0){
      for(i = 0;i< size;i++)
        ((char*)buffer)[i] = input_getc();
      ret = size;
    }
    else if(fd > 2){
        if(thread_current()->fd_table[fd] == NULL){
          lock_release(&file_lock); 
          exit(-1);
        }
        ret = file_read(t->fd_table[fd], buffer, size);
    }
    else {
      lock_release(&file_lock); 
      exit(-1);
    }
    lock_release(&file_lock);
    return ret;
}

static int 
write (int fd, const void *buffer, unsigned size)
{
    int ret = 0;
    struct thread *t = thread_current();
    if(!is_user_vaddr(buffer) || pagedir_get_page(t->pagedir, buffer) == NULL)
        exit(-1);
    lock_acquire(&file_lock);
    if(fd == 1){
        putbuf(buffer, size);
        ret = size;
    }
    else if(fd > 2){
        if(t->fd_table[fd] == NULL){ 
            lock_release(&file_lock); 
            exit(-1);
        }
        if(t->fd_table[fd]->deny_write) 
            file_deny_write(t->fd_table[fd]);
        ret = file_write(t->fd_table[fd], buffer, size);
    }
    else{
      lock_release(&file_lock); 
      exit(-1);
    }
    lock_release(&file_lock);
  return ret;
}

int 
fibonacci(int n)
{
	int xn0 = 0;
  int xn1 = 1;

	if(n <= 0)
		exit(-1);
	if(n == 1)
		return 0;

	for(int i=2;i<=n;i++){
		int xn2 = xn0 + xn1;
		xn0 = xn1;
		xn1 = xn2;
	}
	return xn1;
}

int 
max_of_four_int(int a, int b, int c, int d)
{
	int max1 = a > b ? a : b;
  int max2 = c > d ? c : d;
  return max1 > max2 ? max1 : max2;
}

// 2: 20190258
static bool 
create (const char *file, unsigned initial_size)
{
    struct thread *t = thread_current();
    if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
        exit(-1);
    if(file == NULL) exit(-1);
    return filesys_create(file, (off_t)initial_size);
}

static bool 
remove (const char *file)
{
    struct thread *t = thread_current();
    if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
        exit(-1);
    if(file == NULL) exit(-1);
    return filesys_remove(file);
}

static int 
open (const char *file)
{
    struct thread *t = thread_current();
    struct file *f;
    int i, fd = -1;
    if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
        exit(-1);
    if(file == NULL) exit(-1);
    lock_acquire(&file_lock);
      f = filesys_open(file);
      if(f == NULL) fd = -1;
      else{
        for(int i=3;i<BUF_MAX;i++){
          if(t->fd_table[i] == NULL){
            if(!strcmp(t->name, file)) file_deny_write(f);
            t->fd_table[i] = f;
            fd = i;
            break;
          }
        }
      }	
      lock_release(&file_lock);
    return fd;
}

static int 
filesize (int fd)
{
  struct thread *t = thread_current();
  if(t->fd_table[fd] == NULL) exit(-1);
  return (int)file_length((struct file*)t->fd_table[fd]);
}

static void 
seek (int fd, unsigned position)
{
  struct thread *t = thread_current();
  if(t->fd_table[fd] == NULL) exit(-1);
  file_seek(t->fd_table[fd], position);
}

static unsigned 
tell (int fd)
{
  struct thread *t = thread_current();
  if(t->fd_table[fd] == NULL) exit(-1);
  return file_tell((struct file*)t->fd_table[fd]);
}

static void 
close (int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd] == NULL) exit(-1);
  file_close((struct file*)t->fd_table[fd]);
  t->fd_table[fd] = NULL;
}
