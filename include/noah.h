#ifndef NOAH_H
#define NOAH_H

#ifndef _WIN32
#include <pthread.h>
#endif
#include <cstdint>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>
#include <boost/interprocess/offset_ptr.hpp>
#include <boost/program_options.hpp>

#include "cross_platform.h"
#include "types.h"
#include "util/misc.h"
#include "util/list.h"
#include "util/khash.h"
#include "linux/common.h"
#include "linux/mman.h"
#include "linux/ipc.h"
#include "version.h"

/* privilege management */

void drop_privilege(void);
void elevate_privilege(void);

/* linux emulation */

int do_exec(const char *elf_path, int argc, char *argv[], char **envp);
//int vkern_open(const char *path, int flags, int mode);
//int vkern_openat(int fd, const char *path, int flags, int mode);
//int vkern_close(int fd);
gaddr_t alloc_region(size_t len);

[[noreturn]] void die_with_forcedsig(int sig);
void main_loop(int return_on_sigret);

/* signal */

// #include "linux/signal.h"

/*
typedef atomic_uint_least64_t atomic_sigbits_t;

#define INIT_SIGBIT(sigbit) (*(sigbit) = ATOMIC_VAR_INIT(0))
void handle_signal(void);
bool has_sigpending(void);
int send_signal(pid_t pid, int sig);
*/

/* task related data */

struct task {
  struct list_head head;
  gaddr_t set_child_tid, clear_child_tid;
  uint64_t tid;
  gaddr_t robust_list;
  //l_sigset_t sigmask;
  // atomic_sigbits_t sigpending;
  //l_stack_t sas;
};

struct fdtable {
  int start; // First fd number of this table
  int size;  // Current table size expressed in number of bits
  struct file *files;
  uint64_t *open_fds;
  uint64_t *cloexec_fds;
};

struct fileinfo {
  int rootfd;                      // FS root
  struct fdtable fdtable;          // File descriptors for the user space
  struct fdtable vkern_fdtable;    // File descriptors for the kernel space
  pthread_rwlock_t fdtable_lock;
};

// We manage uid and suid independently on Darwin since we cannot change those of Darwin's freely.
// Wa always hold 0 in Darwin's suid to emulate Linux suid behavior (Note: in the case where Noah has setuid bit).
struct cred {
  pthread_rwlock_t lock;
  l_uid_t uid;
  l_uid_t euid;
  l_uid_t suid;
};

/* for private futex */
struct pfutex_entry {
  struct list_head head;
  pthread_cond_t cond;
  gaddr_t uaddr;
  uint32_t bitset;
};

/* TODO: collect garbage entries */
KHASH_MAP_INIT_INT64(pfutex, struct list_head *)

#ifdef _WIN32
struct platform_proc {
  HANDLE handle;
};
#else
struct platform_proc {
};
#endif

struct proc {
  int nr_tasks;
  struct list_head tasks;
  pthread_rwlock_t lock;
  unsigned pid;
  struct cred cred;
  offset_ptr<struct proc_mm> mm;
  struct {
    pthread_rwlock_t sig_lock;
    // l_sigaction_t sigaction[LINUX_NSIG];
  };
  struct {
    pthread_mutex_t futex_mutex;
    khash_t(pfutex) *pfutex; /* TODO: modify khash and make this field being non-pointer */
  };
  struct fileinfo fileinfo;
  offset_ptr<struct vcpu_state> vcpu_state;  // Used for fork. Should be moved into task afer supporting threads
  platform_proc platform;
};


struct vkern {
  using procs_t = extbuf_map_t<unsigned, offset_ptr<struct proc>>;
  using msrs_t = extbuf_map_t<uint32_t, uint64_t>;

  platform_handle_t shm_handle;
  offset_ptr<extbuf_allocator_t<void>> shm_allocator;

  offset_ptr<msrs_t> msrs;

  // Manage kernel memory space allocated by kmap.
  // Some members related to user memory space such as start_brk are meaningless in this.
  offset_ptr<struct vkern_mm> mm;

  unsigned next_pid;
  offset_ptr<procs_t> procs;
};

static const size_t vkern_shm_size = 0x100000;
extern bip::managed_external_buffer *vkern_shm;
extern struct vkern *vkern;

extern int noah_argc;
extern char **noah_argv;
extern boost::program_options::variables_map noah_opts;

extern struct proc *proc;
_Thread_local extern struct task task;

void init_signal(void);
void reset_signal_state(void);
void init_fileinfo(int rootfd);

void init_fpu(void);

/* Linux kernel constants */

#define LINUX_RELEASE "4.6.4"
#define LINUX_VERSION "#1 SMP PREEMPT Mon Jul 11 19:12:32 CEST 2016" /* FIXME */

#define LINUX_PATH_MAX 4096         /* including null */

/* conversion */

struct stat;
struct l_newstat;
struct statfs;
struct termios;
struct linux_termios;
struct l_statfs;
struct winsize;
struct linux_winsize;
struct rlimit; struct l_rlimit;

int native_to_linux_mprot(int);
int linux_to_native_mprot(int);
int linux_to_native_mflags(int);

#if defined(__unix__) || defined(__APPLE__)
int linux_to_native_o_flags(int l_flags);
#endif


/* debug */

#include "debug.h"

#endif
