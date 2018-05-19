// Basic headers for any host
// Contains host operation and system \
// call interface
#include <lkl_host.h>
#include <lkl.h>

// Some header will get replace with \
// Dce version
#include <pthread.h>
#include <stdlib.h> 
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <poll.h>
#include "iomem.h"
#include "jmp_buf.h"

// Referred from posix-host.c


//TODO: map error number to corresponding \
//      error message if possible.
static int warn_pthread (int ret, char *str_exp)
{
  if (ret > 0)
    lkl_printf ("%s", str_exp);
  return ret;
}

#define WARN_DCE_PTHREAD warn_pthread (exp)

static void print (const char *str, int len) 
{
  ssize_t ret __attribute__((unused));
	// TODO:Need FD as first parameter
	ret = dce_write (0, str, len)
}

static void panic (void)
{
	// Let DCE handle this.
	// Add dce_panic, find correct header in DCE
  return;	
}

// TODO: Need to decide how to SEMAPHORES should be handle in DCE
static struct lkl_sem* sem_alloc (int count)
{
  return NULL;
}

static void sem_free (struct lkl_sem *sem)
{
  return;
}

static void sem_up (struct lkl_sem *sem)
{
  return;
}

static void sem_down (struct lkl_sem *sem)
{
  return;
}

// TODO: Need to decide how to SEMAPHORES should be handle in DCE
static struct lkl_mutex *mutex_alloc (int recursive)
{
  return NULL;
}

static void mutex_free (struct lkl_mutex *mutex)
{
	return;
}

static void mutex_lock (struct lkl_mutex *mutex)
{
  return;
}

static void mutex_unlock (struct lkl_mutex *mutex)
{
  return;
}

static lkl_thread_t thread_create (void (*fn)(void *), void *arg)
{
	// TODO: is warn message set by DCE.
  pthread_t thread;
  //TODO: might need to redefine; because it seems DCE pthread_create \
  //      returns zero only no error number.
  if (WARN_DCE_PTHREAD(dce_pthread_create (&thread, NULL, (void* (*)(void *))fn, arg)))
    return 0;
  else
    return (lkl_thread_t) thread;
    
}

static void thread_detach (void)
{
	WARN_DCE_PTHREAD (dce_pthread_detach (dce_pthread_self ()))
}

//TODO: verify any argument is need rather NULL.
static void thread_exit (void)
{
  dce_pthread_exit (NULL);
}

static int thread_join (lkl_thread_t tid)
{
  if (WARN_DCE_PTHREAD (dce_pthread_join ((pthread_t) tid, NULL)))
    return -1;
  else
    return 0;
}

static lkl_thread_t thread_self (void)
{
  return (lkl_thread_t) dce_pthread_self ()
}

// Note: DCE uses NATIVE version of this function.
//       For now let this function handle by original \
//       pthread library.
// TODO: Check, any room to add this function in DCE (dce-pthread.cc).
static int thread_equal (lkl_thread_t a, lkl_thread_t b)
{
  return pthread_equal ((pthread_t)a, (pthread_t)b);
}

static struct lkl_tls_key *tls_alloc (void (*destructor)(void *))
{
  // TODO: Why POSIX won't typecast to (lkl_tls_key *)
	struct lkl_tls_key *ret = dce_malloc (sizeof (struct lkl_tls_key));
  if (WARN_DCE_PTHREAD (dce_pthread_key_create (&ret->key, destructor)))
  {
    dce_free (ret);
    return NULL;
  }
  return ret;
}

static void tls_free (struct lkl_tls_key *key)
{
  WARN_DCE_PTHREAD (dce_pthread_key_delete (key->key));
  dce_free (key);
}

static int tls_set (struct lkl_tls_key *key, void *data)
{
  if (WARN_DCE_PTHREAD (dce_pthread_setspecific (key->key, data)));
    return -1
  return 0;
}

static void tls_get (struct lkl_tls_key *key)
{
  return dce_pthread_getspecific (key->key);  
}

static void* mem_alloc (unsigned long size)
{
  return dce_malloc ((size_t) size)  
}

// Standard and DCE free method doesn't \
// return any thing.
// TODO: What should be the return value here?
static void mem_free (void * ptr)
{
  dce_free (ptr);
  // for now success always
  return 0;
}

static unsigned long long time (void)
{
  struct timespace ts;
  // TODO: check which clk id best suits in DCE
  dce_clock_gettime (CLOCK_MONOTONIC, &ts);
  return 1e9*ts.tv_sec + ts.tv_nsec;
}

static void* timer_alloc (void (*fn)(void *), void *arg)
{
  int err;
  timer_t timer;
  struct sigevent se = {
    .sigev_notify = SIGEV_THREAD,
    .sigev_value = {
      .sival_ptr = arg,
    },
    .sigev_notify_function = (void (*)(union sigval))fn;
  };
  err = dce_timer_create (CLOCK_REALTIME, &se, &timer);
  if (err)
    return NULL:
  // TODO: why directly typecast into (void *)
  return (void *)(long) timer;
}

static int timer_set_oneshot (void *timer, unsigned long delta)
{
  timer_t timer = (timer_t)(long)_timer;
  struct itimerspec ts = {
    .it_value = {
      .tv_sec = ns / 1000000000,
      .tv_nsec = ns % 1000000000,
    },
  };
  return dce_timer_settime(timer, 0, &ts, NULL);
}

// dce_timer_delete not found
// TODO: try to find workaround
static void timer_free (void *timer)
{
  return;
}

// @ioremap - searches for an I/O memory region identified by addr and size and
// returns a pointer to the start of the address range that can be used by
// iomem_access
static void* ioremap (long addr, int size)
{
  // As such not need;
  // TODO:discuss and descibe some action
}

// @iomem_acess - reads or writes to and I/O memory region; addr must be in the
// * range returned by ioremap
static int iomem_access (const volatile void *addr, void *val, int size, int write)
{
  // As such not need;
  // TODO:discuss and descibe some action
}

static long gettid (void)
{
  return (long) dce_pthread_self ();  
}

// @jmp_buf_set - runs the give function and setups a jump back point by saving
// the context in the jump buffer; jmp_buf_longjmp can be called from the give
// function or any callee in that function to return back to the jump back
// point
static void jmp_buf_set (struct lkl_jmp_buf *jmpb, void (*f)(void))
{
  // Seems relevant to dce, not sure how to handle;
  return;
}

static void jmp_buf_longjmp (struct lkl_jmp_buf *jmpb, int val)
{
  // Seems relevant to dce, not sure how to handle;
  return;
}


struct lkl_host_operations lkl_host_ops = {
  // TODO: verify the usage
  const char *virtio_devices;

  .print = print;
  .panic = panic;
  .lkl_sem = lkl_sem;
  .sem_free = sem_free;
  .sem_up = sem_up;
  .sem_down = sem_down;
  .lkl_mutex = lkl_mutex;
  .mutex_free = mutex_free;
  .mutex_lock = mutex_lock;
  .mutex_unlock = mutex_unlock;
  .thread_create = thread_create;
  .thread_detach = thread_detach;
  .thread_exit = thread_exit;
  .thread_join = thread_join;
  .thread_self = thread_self;
  .thread_equal = thread_equal;
  .tls_alloc = tls_alloc;
  .tls_free = tls_free;
  .tls_set = tls_set;
  .tls_get = tls_get
  .mem_alloc = mem_alloc;
  .mem_free = mem_free;
  .time = time;
  .timer_alloc = timer_alloc;
  .timer_set_oneshot = timer_set_oneshot;
  .timer_free = timer_free;
  .ioremap = ioremap;
  .iomem_access = iomem_access
  .gettid = gettid;
  .jmp_buf_set = jmp_buf_set;
  .jmp_buf_longjmp = jmp_buf_longjmp;
};

