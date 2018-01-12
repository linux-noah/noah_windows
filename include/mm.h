#ifndef NOAH_MM_H
#define NOAH_MM_H

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif
#include <cstdbool>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>

#include "cross_platform.h"
#include "types.h"
#include "noah.h"

namespace bip = boost::interprocess;

using bip::offset_ptr;

/* interface to user memory */

void *guest_to_host(gaddr_t);

#define VERIFY_READ  LINUX_PROT_READ
#define VERIFY_WRITE LINUX_PROT_WRITE
#define VERIFY_EXEC  LINUX_PROT_EXEC
bool addr_ok(gaddr_t, int verify);

size_t copy_from_user(void *haddr, gaddr_t gaddr, size_t n); /* returns 0 on success */
ssize_t strncpy_from_user(void *haddr, gaddr_t gaddr, size_t n);
size_t copy_to_user(gaddr_t gaddr, const void *haddr, size_t n);
ssize_t strnlen_user(gaddr_t gaddr, size_t n);

/* memory related structures */

struct mm_region {
  platform_handle_t handle;
  void *haddr;
  gaddr_t gaddr;
  size_t size;
  int prot;            /* Access permission that consists of LINUX_PROT_* */
  int mm_flags;        /* mm flags in the form of LINUX_MAP_* */
  int mm_fd;
  int pgoff;           /* offset within mm_fd in page size */
  bool is_global;      /* global page flag. Preserved during exec if global */
};

struct mm {
  using mm_regions_key_t = std::pair<gaddr_t, gaddr_t>;
  using mm_regions_t = extbuf_map_t<mm_regions_key_t, offset_ptr<mm_region>, std::function<bool(mm_regions_key_t, mm_regions_key_t)>>;
  using mm_regions_iter_t = mm::mm_regions_t::iterator;

  offset_ptr<mm_regions_t> mm_regions;
  uint64_t start_brk, current_brk;
  uint64_t current_mmap_top;
  pthread_rwlock_t alloc_lock;
};

extern const gaddr_t user_addr_max;

void init_page();
void init_segment();
void init_mm(struct mm *mm);
void copy_mm(struct mm *dst_mm, struct mm *src_mm);

gaddr_t kmap(void *ptr, platform_handle_t handle, size_t size, int flags);

int region_compare(const struct mm_region *r1, const struct mm_region *r2);
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm);
std::pair<mm::mm_regions_iter_t, mm::mm_regions_iter_t> find_region_range(gaddr_t gaddr, size_t size, struct mm *mm);
struct mm_region *record_region(struct mm *mm, platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff);
std::pair<mm_region *, mm_region *> split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr);
void destroy_mm(struct mm *mm);

bool is_region_private(struct mm_region*);

gaddr_t do_mmap(gaddr_t addr, size_t len, int d_prot, int l_prot, int l_flags, int fd, off_t offset);
int do_munmap(gaddr_t gaddr, size_t size);


#ifdef _WIN32

// Temporalily map constants from POSIX's to Windows's
#ifndef PROT_READ  // libhypervisor could define PROT_READ as the same values
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4
#define PROT_NONE  0x0
#endif

#define MAP_INHERIT       1
#define MAP_FILE_SHARED   2
#define MAP_FILE_PRIVATE  4

#endif

/* platform_mflags flag is
 * 1. In UNIX
 *   native mflags
 * 2. In Windows
 *   a value that consists of the following bits
 *     - MAP_INHERIT
 *     - MAP_FILE_SHARED
 *     - MAP_FILE_PRIVATE
 */
int platform_map_mem(void **ret, platform_handle_t *handle, size_t size, int prot, int platform_mflags);
int platform_alloc_filemapping(void **ret, platform_handle_t *handle, ssize_t size, int prot, int platform_mflags, off_t offset, const char *path);
int platform_unmap_mem(void *mem, platform_handle_t handle, size_t size);
int platform_free_filemapping(void *addr, platform_handle_t handle, size_t size);

#endif
