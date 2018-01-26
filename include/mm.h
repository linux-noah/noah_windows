#ifndef NOAH_MM_H
#define NOAH_MM_H

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif
#include <cstdbool>
#include <atomic>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/smart_ptr/shared_ptr.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>

#include "cross_platform.h"
#include "types.h"
#include "noah.h"
#include "x86/vm.h"

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

class host_handle {
public:
  platform_handle_t handle;

  host_handle(platform_handle_t handle) {
    this->handle = handle;
  };
  virtual ~host_handle() {
#ifdef _WIN32
    CloseHandle(handle);
#else
    close(handle);
#endif
  };
};

template <typename T>
struct range_less {
  using range_t = pair<T, T>;
  bool operator()(const range_t &r1, const range_t &r2) const { return r1.second <= r2.first; };
};

template <typename T, typename V>
class discrete_range_map : 
  private extbuf_map_t<typename range_less<T>::range_t, V, typename range_less<T>> 
{
public:
  using range_t    = typename range_less<T>::range_t;
  using range_less = typename range_less<T>;
  using val_t      = V;
  using map_t      = typename extbuf_map_t<range_t, V, range_less>;
  using iterator   = typename map_t::iterator;

  using map_t::insert;
  using map_t::emplace;
  using map_t::erase;
  using map_t::find;
  using map_t::equal_range;
  using map_t::begin;
  using map_t::cbegin;
  using map_t::end;
  using map_t::cend;
  void set_range(range_t key, void* val) {};
  void erase_range(range_t key) {};
  pair<map_t::iterator, map_t::iterator> split(const range_t &range, gaddr_t split_point) {
    auto itr = this->find(range);
    auto head_node = this->extract(itr);
    head_node.key() = range_t(range.first, split_point);
    auto head = this->insert(std::move(head_node));
    auto tail = this->emplace(range_t(split_point, range.second), itr->second);
    return pair<discrete_range_map::iterator, discrete_range_map::iterator>(head.position, tail.first);
  };

  discrete_range_map() :
    discrete_range_map::map_t(range_less(), *vkern->shm_allocator)
  {}
};

class range_refcount : public discrete_range_map<gaddr_t, uint> {
public:

  gaddr_t size;

  range_refcount(gaddr_t size) :
    size(size) 
  {};

  uint incref(range_t range) { return 0;/*TODO*/ };
  uint decref(range_t range) {
    /*auto overlap_iter = mapping_counter->equal_range(range);
    while (overlap_iter.first != overlap_iter.second) {
      auto cur = overlap_iter.first++;
      auto overlapping = cur->first;

      if (overlapping.first < range.first) {
        split(cur, range.first);
        //overlapping = split_region(proc->mm.get(), overlapping, range.first).second;
      }
      if (overlapping.second > range.second) {
        split(cur, range.second);
        //overlapping = split_region(proc->mm.get(), overlapping, gaddr + size).first;
      }
      cur->second--;
    }*/
    return 0;
  };
};

class host_filemap_handle : public host_handle {
public:
  using range_t    = range_less<gaddr_t>::range_t;

  range_refcount map_refcount;
  mutex_t        map_mutex;

  host_filemap_handle(platform_handle_t handle, size_t size) :
    host_handle(handle), map_refcount(size)
  {};

  uint map(range_t range) { return 0; };
  uint unmap(range_t range) { return 0; };
};

using host_fmappings_t = discrete_range_map<gaddr_t, pair<void *, shared_ptr<host_filemap_handle>>>;

struct mm_region {

  platform_handle_t handle;
  host_fmappings_t host_fmappings;
  /* If this region is a global mapping, haddr_offset is used instead of haddr. */
  void *haddr;
  offset_ptr<void> haddr_offset;
  gaddr_t gaddr;
  size_t size;
  int prot;            /* Access permission that consists of LINUX_PROT_* */
  int mm_flags;        /* mm flags in the form of LINUX_MAP_* */
  int mm_fd;
  int pgoff;           /* offset within mm_fd in page size */
  bool is_global;

public:
  mm_region(platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff, bool is_global);
};

struct mm {
  using regions_key_t  = pair<gaddr_t, gaddr_t>;
  struct regions_key_less {
    bool operator()(const mm::regions_key_t &r1, const mm::regions_key_t &r2) const { return r1.second <= r2.first; };
  };
  using regions_t      = extbuf_map_t<regions_key_t, offset_ptr<mm_region>, regions_key_less>;
  using regions_iter_t = mm::regions_t::iterator;

  regions_t regions;
  bool      is_global;  /* If true, the mappings are global */

  uint64_t  start_brk, current_brk;

  mutex_t mutex;

public:
  mm(bool is_glboal);
  mm() : mm(false) {};
  virtual ~mm();
};

struct proc_mm : public mm {
  uint64_t current_mmap_top;

public:
  proc_mm();
};


struct vkern_mm : public mm {
  gaddr_t exception_entry_addr;
  gaddr_t syscall_entry_addr;
  gaddr_t gdt_addr;
  gaddr_t idt_addr;
  gaddr_t pml4_addr;

public:
  vkern_mm();
};

extern const gaddr_t user_addr_max;

void init_page();
void init_segment();
void restore_mm(struct mm *mm);
void clone_mm(struct mm *dst_mm, struct mm *src_mm);

gaddr_t kmap(void *ptr, platform_handle_t handle, size_t size, int flags);
template <typename T>
gaddr_t
kalloc_aligned(T **ptr, int flags, int size, int align)
{
  *ptr = reinterpret_cast<T *>(vkern_shm->allocate_aligned(size, align));
  return kmap(*ptr, PLATFORM_INVALID_HANDLE, size, flags);
}
template <typename T>
gaddr_t
kalloc_aligned(T **ptr, int flags)
{
  return kalloc_aligned(ptr, flags, sizeof(T), PAGE_SIZE(PAGE_4KB));
}

int region_compare(const struct mm_region *r1, const struct mm_region *r2);
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm);
pair<mm::regions_iter_t, mm::regions_iter_t> find_region_range(gaddr_t gaddr, size_t size, struct mm *mm);
struct mm_region *record_region(struct mm *mm, platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff);
pair<mm_region *, mm_region *> split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr);

bool is_region_private(struct mm_region*);
void *mm_region_haddr(struct mm_region*, gaddr_t);

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
#ifdef _WIN32
int platform_restore_mapped_mem(void **ret, platform_handle_t handle, size_t size, int prot, int platform_mflags);
#endif

#endif
