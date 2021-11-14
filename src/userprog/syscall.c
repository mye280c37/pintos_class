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
static void valid_fd(struct thread *t, int fd); 

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

static void 
valid_fd(struct thread *t, int fd)
{
  if (fd <3 || fd > BUF_MAX) exit(-1);
  if(t->fd_table[fd] == NULL) exit(-1);
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
  struct file *fp;
  
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
      if(!is_user_vaddr(*(char**)(f->esp+4)) || pagedir_get_page(t->pagedir, *(char**)(f->esp+4)) == NULL)
        exit(-1);
      f->eax = process_execute(*(char **)(f->esp +4)); 
      //f->eax = exec(*(char**)(f->esp+4));
      break;
	  case SYS_WAIT:
      check_memory_access(f->esp, t, 1);
      f->eax = process_wait(*(tid_t *)(f->esp+4));
      //f->eax = wait(*(tid_t *)(f->esp+4));
      break;
	  case SYS_CREATE:
      check_memory_access(f->esp, t, 2);
      if(!is_user_vaddr((*(char**)(f->esp+4))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+4))) == NULL)
        exit(-1);
      if(*(char **)(f->esp+4) == NULL) exit(-1);
      f->eax = filesys_create(*(char **)(f->esp+4), *(off_t *)(f->esp+8));
      //f->eax = create(*(char**)(f->esp+4), *(unsigned*)(f->esp+8));
      break;
	  case SYS_REMOVE:
      check_memory_access(f->esp, t, 1);
      if(!is_user_vaddr((*(char**)(f->esp+4))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+4))) == NULL)
        exit(-1);
      if(*(char **)(f->esp+4) == NULL) exit(-1);
      f->eax = filesys_remove(*(char **)(f->esp+4));
      //f->eax = remove(*(char**)(f->esp+4));
      break;
	  case SYS_OPEN:
	  	check_memory_access(f->esp, t, 1);
      if(!is_user_vaddr(*(char**)(f->esp+4)) || pagedir_get_page(t->pagedir, *(char **)(f->esp+4)) == NULL)
        exit(-1);
      if(*(char **)(f->esp+4) == NULL) exit(-1);
      f->eax = -1;
      lock_acquire(&file_lock);
      fp = filesys_open(*(char **)(f->esp+4));
      if(fp == NULL) f->eax = -1;
      else{
        for(int i=3;i<131;i++){
          if(thread_current()->fd_table[i] == NULL){
            if(!strcmp(thread_current()->name, *(char **)(f->esp+4))) file_deny_write(fp);
            thread_current()->fd_table[i] = fp;
            f->eax = i;
            break;
          }
        }
      }	
      lock_release(&file_lock);
      //f->eax = open(*(char**)(f->esp+4));
      break;
	  case SYS_FILESIZE:
	  	check_memory_access(f->esp, t, 1);
      fp = thread_current()->fd_table[*(int *)(f->esp+4)];
      if(fp == NULL) exit(-1);
      else f->eax = file_length(fp);
		  //f->eax = filesize(*(int*)(f->esp+4));
		  break;
	  case SYS_READ:
	  	check_memory_access(f->esp, t, 3);
      if(!is_user_vaddr((*(char **)(f->esp+8))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+8))) == NULL)
        exit(-1);
      f->eax = -1;//initialize
      lock_acquire(&file_lock);
      if((int)*(uint32_t *)(f->esp+4) == 0){
        for(int i = 0;i< *(int *)(f->esp+12);i++)
          (*(char **)(f->esp+8))[i] = input_getc();
        f->eax = *(int *)(f->esp+12);
      }
      else if((int)*(uint32_t *)(f->esp+4) > 2){
        if(thread_current()->fd_table[*(int *)(f->esp+4)] == NULL){
          lock_release(&file_lock); 
          exit(-1);
        }
        f->eax = file_read(thread_current()->fd_table[*(int *)(f->esp+4)], *(void **)(f->esp+8), *(off_t *)(f->esp+12));
      }
      lock_release(&file_lock);
      //f->eax = read((int)*(uint32_t *)(f->esp+4), *(void**)(f->esp+8), *(unsigned*)(f->esp+12));
		  break;
	  case SYS_WRITE:
	  	check_memory_access(f->esp, t, 3);
      if(!is_user_vaddr((void *)*(uint32_t *)(f->esp+8)) || pagedir_get_page(t->pagedir, (void *)*(uint32_t *)(f->esp+8)) == NULL)
        exit(-1);
      f->eax = -1;
      lock_acquire(&file_lock);
      if((int)*(uint32_t *)(f->esp+4) == 1){
        putbuf((void *)*(uint32_t *)(f->esp+8), *(size_t *)(f->esp+12));
      }
      else if((int)*(uint32_t *)(f->esp+4) > 2){
        if(thread_current()->fd_table[*(int *)(f->esp+4)] == NULL){ 
          lock_release(&file_lock); exit(-1);
        }
        if(thread_current()->fd_table[*(int *)(f->esp+4)]->deny_write) 
          file_deny_write(thread_current()->fd_table[*(int *)(f->esp+4)]);
        f->eax = file_write(thread_current()->fd_table[*(int *)(f->esp+4)], *(void **)(f->esp+8), *(off_t *)(f->esp+12));
      }
      lock_release(&file_lock);
		  //f->eax = write(*(int*)(f->esp+4), (void *)*(uint32_t *)(f->esp+8), *(unsigned*)(f->esp+12));
		  break;
	  case SYS_SEEK:
	  	check_memory_access(f->esp, t, 2);
      if(thread_current()->fd_table[*(int *)(f->esp+4)] == NULL) exit(-1);
      file_seek(thread_current()->fd_table[*(int *)(f->esp+4)], *(off_t *)(f->esp+8));
		  //seek(*(int*)(f->esp+4), *(unsigned*)(f->esp+8));
		  break;
	  case SYS_TELL:
	  	check_memory_access(f->esp, t, 1);
      if(thread_current()->fd_table[*(int *)(f->esp+4)] == NULL) exit(-1);
      f->eax = file_tell(thread_current()->fd_table[*(int *)(f->esp+4)]);
		  //f->eax = tell(*(int*)(f->esp+4));
		  break;
	  case SYS_CLOSE:
	  	check_memory_access(f->esp, t, 1);
      //if((*(int *)(f->esp+4))<0||(*(int *)(f->esp+4))>=131) exit(-1);
      if(thread_current()->fd_table[*(int *)(f->esp+4)] == NULL) exit(-1);
      //lock_acquire(&file_lock);
      file_close(thread_current()->fd_table[*(int *)(f->esp+4)]);
      thread_current()->fd_table[*(int *)(f->esp+4)] = NULL;//close file
      //lock_release(&file_lock);
      // close(*(int*)(f->esp+4));
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
  // while(e != list_end(&(t->children))){
	//   child = list_entry(e, struct thread, child_elem);
	//   process_wait(child->tid);
  // }
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);

  thread_exit();
}

static pid_t 
exec (const char *file)
{
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
  unsigned i;
  int ret = -1;
  struct thread *t = thread_current();
  // if(!is_user_vaddr(buffer || pagedir_get_page(t->pagedir, buffer) == NULL))
  //     exit(-1);
  //if(buffer == NULL) exit(-1);
  //check_memory_access(buffer, t, 0);
  lock_acquire(&file_lock);
  if (fd == 0)
  {
    for(i=0; i<size; i++){
      *(uint8_t*)buffer = input_getc();
      buffer+=sizeof(uint8_t);
    }
    ret = size;
  }
  // 2: 20190258
  else if(fd > 2){
	valid_fd(t, fd);
    ret = file_read(t->fd_table[fd], buffer, size);
  }
  lock_release(&file_lock);
  return ret;
}

static int 
write (int fd, const void *buffer, unsigned size)
{
  int ret = -1;
  struct thread *t = thread_current();
  // if(!is_user_vaddr(buffer || pagedir_get_page(t->pagedir, buffer) == NULL))
  //     exit(-1);
//   if(!is_user_vaddr(buffer) || pagedir_get_page(t->pagedir, buffer) == NULL)
// 	exit(-1);
//   if(buffer == NULL) exit(-1);
  //check_memory_access(buffer, t, 0);
  lock_acquire(&file_lock);
  if (fd == 1)
  {
    putbuf(buffer, size);
    ret = size;
  }
  else if (fd > 2){
	valid_fd(t, fd);
    ret = file_write(t->fd_table[fd], buffer, size);
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
  
//   check_memory_access(file, t, 0);
//   if(!is_user_vaddr((char*)file) || pagedir_get_page(t->pagedir, (char*)file) == NULL)
// 	exit(-1);
//   if(file == NULL) exit(-1);
  return filesys_create(file, (off_t)initial_size);
}

static bool 
remove (const char *file)
{
  struct thread *t = thread_current();
//   if(!is_user_vaddr((char*)file) || pagedir_get_page(t->pagedir, (char*)file) == NULL)
// 	exit(-1);
//   if(file == NULL) exit(-1);
  return filesys_remove(file);
}

static int 
open (const char *file)
{
  struct thread *t = thread_current();
  int i, fd = -1;
//   if(!is_user_vaddr((char*)file) || pagedir_get_page(t->pagedir, (char*)file) == NULL)
// 	exit(-1);
//   if(file == NULL) exit(-1);
  lock_acquire(&file_lock);
  struct file* f = filesys_open(file);
  if(f==NULL) fd = -1;
  else{
    for(i=3; i<BUF_MAX; i++){
      if(t->fd_table[i] == NULL){
        if(strcmp(t->name, file) == 0){
          file_deny_write(f); // why?
        }
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
  valid_fd(t, fd);
  return (int)file_length((struct file*)t->fd_table[fd]);
}

static void 
seek (int fd, unsigned position)
{
  struct thread *t = thread_current();
  valid_fd(t, fd);
  file_seek((struct file*)fd, position);
}

static unsigned 
tell (int fd)
{
  struct thread *t = thread_current();
  valid_fd(t, fd);
  return file_tell((struct file*)fd);
}

static void 
close (int fd)
{
  struct thread* t = thread_current();
  valid_fd(t, fd);
  file_close((struct file*)t->fd_table[fd]);
  t->fd_table[fd] = NULL;
}
