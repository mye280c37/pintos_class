#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
// 1: halt, exit, exec, wait, read, write - 20192058
static void memory_access_check(void *esp, struct thread *t, int c);
static void halt (void);
static void exit (int status); 
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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void 
memory_access_check(void *esp, struct thread *t, int c){
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
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *t = thread_current();
  memory_access_check(f->esp, t, 0);

  int sys_num = *(int *)(f->esp);
  switch(sys_num){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      memory_access_check(f->esp, t, 1);
      exit(*(int*)(f->esp+4));
      break;
    case SYS_EXEC:
      memory_access_check(f->esp, t, 1);
      f->eax = exec(*(char**)(f->esp+4));
      break;
    case SYS_WAIT:
      memory_access_check(f->esp, t, 1);
      f->eax = wait(*(pid_t*)(f->esp+4));
      break;
    case SYS_CREATE:
      memory_access_check(f->esp, t, 2);
      f->eax = create(*(char**)(f->esp+4), *(unsigned*)(f->esp+8));
      break;
    case SYS_REMOVE:
      memory_access_check(f->esp, t, 1);
      f->eax = remove(*(char**)(f->esp+4));
      break;
    case SYS_OPEN:
      memory_access_check(f->esp, t, 1);
      f->eax = open(*(char**)(f->esp+4));
      break;
    case SYS_FILESIZE:
      memory_access_check(f->esp, t, 1);
      f->eax = filesize(*(int*)(f->esp+4));
      break;
    case SYS_READ:
      memory_access_check(f->esp, t, 3);
      f->eax = read(*(int*)(f->esp+4), *(void**)(f->esp+8), *(unsigned*)(f->esp+12));
      break;
    case SYS_WRITE:
      memory_access_check(f->esp, t, 3);
      f->eax = write(*(int*)(f->esp+4), *(void**)(f->esp+8), *(unsigned*)(f->esp+12));
      break;
    case SYS_SEEK:
      memory_access_check(f->esp, t, 2);
      seek(*(int*)(f->esp+4), *(unsigned*)(f->esp+8));
      break;
    case SYS_TELL:
      memory_access_check(f->esp, t, 1);
      f->eax = tell(*(int*)(f->esp+4));
      break;
    case SYS_CLOSE:
      memory_access_check(f->esp, t, 1);
      close(*(int*)(f->esp+4));
      break;
    case SYS_FIBONACCI:
      memory_access_check(f->esp, t, 1);
      f->eax = fibonacci(*(int*)(f->esp+4));
      break;
    case SYS_MAX_OF_FOUR_INT:
      memory_access_check(f->esp, t, 4);
      f->eax = max_of_four_int(*(int*)(f->esp+4), *(int*)(f->esp+8), *(int*)(f->esp+16), *(int*)(f->esp+20));
      break;
	default:
	  thread_exit();
  }
}

static void 
halt (void)
{
  shutdown_power_off();
}

static void 
exit (int status)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);
  t->exit_status = status;

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
  unsigned i;
  struct thread *t = thread_current();
  if(!is_user_vaddr(buffer || pagedir_get_page(t->pagedir, buffer) == NULL))
      exit(-1);
  if (fd == 0)
  {
    for(i=0; i<size; i++){
      *(uint8_t*)buffer = input_getc();
      buffer+=sizeof(uint8_t);
    }
    return size;
  }
  else exit(-1);
}

static int 
write (int fd, const void *buffer, unsigned size)
{
  struct thread *t = thread_current();
  if(!is_user_vaddr(buffer || pagedir_get_page(t->pagedir, buffer) == NULL))
      exit(-1);
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  else exit(-1);
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
  return filesys_create(file, initial_size);
}

static bool 
remove (const char *file)
{
  struct thread *t = thread_current();
  if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
      exit(-1);
  return filesys_remove(file);
}

static int 
open (const char *file)
{
  struct thread *t = thread_current();
  if(!is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
      exit(-1);
  //struct file* targ_file = filesys_open(file);
  return filesys_open(file);
}

static int 
filesize (int fd)
{
  return file_length((struct file*)fd);
}

static void 
seek (int fd, unsigned position)
{
  file_seek((struct file*)fd, position);
}

static unsigned 
tell (int fd)
{
  return file_tell((struct file*)fd);
}

static void 
close (int fd)
{
  file_close((struct file*)fd);
}
