#include <cassert>
#include <cstdlib>
#include <boost/interprocess/managed_external_buffer.hpp>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <cstring>
#endif

#include "mm.hpp"
#include "cross_platform.h"
#include "common.h"
#include "util/list.h"
#include "vm.h"
#include "noah.h"
#include "mm.h"

#include "linux/mman.h"

#include "x86/vm.h"
#include "x86/specialreg.h"

namespace bi = boost::interprocess;

/* 
 * Manage kernel memory space allocated by kmap.
 * Some members related to user memory space such as start_brk are meaningless in vkern_mm.
 */
struct mm vkern_mm;
bi::managed_external_buffer *vkern_shm;
platform_handle_t vkern_shm_handle;

void init_mmap(struct mm *mm);

const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

gaddr_t
kmap(void *ptr, platform_handle_t handle, size_t size, int flags)
{
  static uint64_t noah_kern_brk = 0x0000007fc0000000ULL; // user_addr_max, hard coding for a workaroud of MSVC's complaining

  assert((size & 0xfff) == 0);
  assert(((uint64_t) ptr & 0xfff) == 0);

  pthread_rwlock_wrlock(&vkern_mm.alloc_lock);

  record_region(&vkern_mm, handle, ptr, noah_kern_brk, size, native_to_linux_mprot(flags), -1, -1, 0);
  vm_mmap(noah_kern_brk, size, flags, ptr);
  noah_kern_brk += size;

  pthread_rwlock_unlock(&vkern_mm.alloc_lock);

  return noah_kern_brk - size;
}

TYPEDEF_PAGE_ALIGNED(uint64_t) pe_t[NR_PAGE_ENTRY];
pe_t *pml4;
gaddr_t pml4_ptr;
pe_t *pdp;
gaddr_t pdp_ptr;

void
init_page()
{
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT;
#else
  const int platform_mflags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif
  int err;
  platform_handle_t pml4_handle, pdp_handle;
  err = platform_map_mem(reinterpret_cast<void **>(&pml4), &pml4_handle, sizeof(pe_t), PROT_READ | PROT_WRITE, platform_mflags);
  if (err < 0) {
    abort();
  }
  err = platform_map_mem(reinterpret_cast<void **>(&pdp), &pdp_handle, sizeof(pe_t), PROT_READ | PROT_WRITE, platform_mflags);
  if (err < 0) {
    abort();
  }
  pml4_ptr = kmap(pml4, pml4_handle, 0x1000, PROT_READ | PROT_WRITE);
  pdp_ptr = kmap(pdp, pdp_handle, 0x1000, PROT_READ | PROT_WRITE);
  
  // Straight mapping
  (*pml4)[0] = (pdp_ptr & 0x000ffffffffff000ul) | PTE_U | PTE_W | PTE_P;
  for (int i = 0; i < NR_PAGE_ENTRY; i++) {
    (*pdp)[i] = (0x40000000ULL * i) | PTE_PS | PTE_U | PTE_W | PTE_P;
  }
  (*pdp)[NR_PAGE_ENTRY - 1] &= ~PTE_U; // the region that kmap manages

  write_register(VMM_X64_CR0, CR0_PG | CR0_PE | CR0_NE);
  write_register(VMM_X64_CR3, pml4_ptr);
}

TYPEDEF_PAGE_ALIGNED(uint64_t) gdt_t[3];
gdt_t *gdt;
gaddr_t gdt_ptr;

void
init_segment()
{
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT;
#else
  const int platform_mflags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif
  int err;
  platform_handle_t handle;
  err = platform_map_mem(reinterpret_cast<void **>(&gdt), &handle, sizeof(gdt_t), PROT_READ | PROT_WRITE, platform_mflags);
  if (err < 0) {
    abort();
  }
  (*gdt)[SEG_NULL] = 0;
  (*gdt)[SEG_CODE] = 0x0020980000000000;
  (*gdt)[SEG_DATA] = 0x0000900000000000;

  gdt_ptr = kmap(gdt, handle, 0x1000, PROT_READ | PROT_WRITE);

  write_register(VMM_X64_GDT_BASE, gdt_ptr);
  write_register(VMM_X64_GDT_LIMIT, 3 * 8 - 1);

  write_register(VMM_X64_TR, 0);
  write_register(VMM_X64_TSS_BASE, 0);
  write_register(VMM_X64_TSS_LIMIT, 0);
  write_register(VMM_X64_TSS_AR, 0x0000008b);

  static const uint64_t desc_unusable = 0x00010000;
  static const uint32_t code_ar = 0x0000209B;
  static const uint32_t data_ar = 0x00000093;

  write_register(VMM_X64_LDT_BASE, 0);
  write_register(VMM_X64_LDT_LIMIT, 0);
  write_register(VMM_X64_LDT_AR, desc_unusable);

  write_register(VMM_X64_IDT_BASE, 0);
  write_register(VMM_X64_IDT_LIMIT, 0xffff);

  write_register(VMM_X64_CS, 0x8);
  write_register(VMM_X64_CS_BASE, 0);
  write_register(VMM_X64_CS_LIMIT, 0);
  write_register(VMM_X64_CS_AR, code_ar);

  write_register(VMM_X64_DS, 0x10);
  write_register(VMM_X64_DS_BASE, 0);
  write_register(VMM_X64_DS_LIMIT, 0);
  write_register(VMM_X64_DS_AR, data_ar);

  write_register(VMM_X64_ES, 0x10);
  write_register(VMM_X64_ES_BASE, 0);
  write_register(VMM_X64_ES_LIMIT, 0);
  write_register(VMM_X64_ES_AR, data_ar);

  write_register(VMM_X64_FS, 0x10);
  write_register(VMM_X64_FS_BASE, 0);
  write_register(VMM_X64_FS_LIMIT, 0);
  write_register(VMM_X64_FS_AR, data_ar);

  write_register(VMM_X64_GS, 0x10);
  write_register(VMM_X64_GS_BASE, 0);
  write_register(VMM_X64_GS_LIMIT, 0);
  write_register(VMM_X64_GS_AR, data_ar);

  write_register(VMM_X64_SS, 0x10);
  write_register(VMM_X64_SS_BASE, 0);
  write_register(VMM_X64_SS_LIMIT, 0);
  write_register(VMM_X64_SS_AR, data_ar);

  write_register(VMM_X64_CS, GSEL(SEG_CODE, 0));
  write_register(VMM_X64_DS, GSEL(SEG_DATA, 0));
  write_register(VMM_X64_ES, GSEL(SEG_DATA, 0));
  write_register(VMM_X64_FS, GSEL(SEG_DATA, 0));
  write_register(VMM_X64_GS, GSEL(SEG_DATA, 0));
  write_register(VMM_X64_SS, GSEL(SEG_DATA, 0));
  write_register(VMM_X64_TR, 0);
  write_register(VMM_X64_LDTR, 0);
}

void
init_mm(struct mm *mm)
{
  memset(mm, 0, sizeof(struct mm));
  init_mmap(mm);

  INIT_LIST_HEAD(&mm->mm_regions);
  RB_INIT(&mm->mm_region_tree);
  pthread_rwlock_init(&mm->alloc_lock, NULL);
}

void
init_vkern_shm()
{
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT;
#else
  const int platform_mflags = MAP_SHARED | MAP_ANONYMOUS;
#endif
  void *buf;
  int err = platform_map_mem(&buf, &vkern_shm_handle, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, platform_mflags);
  if (err < 0) {
    abort();
  }
  vkern_shm = new bi::managed_external_buffer(bi::create_only, buf, 0x1000000);
}

void *
guest_to_host(gaddr_t gaddr)
{
  struct mm_region *region = find_region(gaddr, proc->mm);
  if (!region) {
    region = find_region(gaddr, &vkern_mm);
  }
  if (!region) {
    return NULL;
  }
  return (char *)region->haddr + gaddr - region->gaddr;
}

int
region_compare(struct mm_region *r1, struct mm_region *r2)
{
  if (r1->gaddr >= r2->gaddr + r2->size) {
    return 1;
  }
  if (r1->gaddr + r1->size <= r2->gaddr) {
    return -1;
  }
  
  return 0;
}

RB_GENERATE(mm_region_tree, mm_region, tree, region_compare);

struct mm_region*
/* Look up the mm_region which gaddr in [mm_region->gaddr, +size) */
find_region(gaddr_t gaddr, struct mm *mm)
{
  struct mm_region find;
  find.gaddr = gaddr;
  find.size = 1;
  return RB_FIND(mm_region_tree, &mm->mm_region_tree, &find);
}

struct mm_region*
/* Look up the lowest mm_region that overlaps with the region */
find_region_range(gaddr_t gaddr, size_t size, struct mm *mm)
{
  struct mm_region find;
  find.gaddr = gaddr;
  find.size = size;
  struct mm_region *leftmost = RB_FIND(mm_region_tree, &mm->mm_region_tree, &find);
  if (leftmost == NULL)
    return NULL;
  while (RB_LEFT(leftmost, tree) != NULL && region_compare(&find, RB_LEFT(leftmost, tree)) == 0)
    leftmost = RB_LEFT(leftmost, tree);
  return leftmost;
}

void
split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr)
{
  assert(is_page_aligned((void*)gaddr, PAGE_4KB));

  struct mm_region *tail = reinterpret_cast<struct mm_region *>(malloc(sizeof(struct mm_region)));
  gaddr_t offset = gaddr - region->gaddr;
  tail->haddr = (char *)region->haddr + offset;
  tail->gaddr = gaddr;
  tail->size = region->size - offset;
  tail->prot = region->prot;
  tail->mm_flags = region->mm_flags;
  tail->mm_fd = region->mm_fd;
  tail->pgoff = region->pgoff;

  region->size = offset;
  list_add(&tail->list, &region->list);
  RB_INSERT(mm_region_tree, &mm->mm_region_tree, tail);
}

struct mm_region*
record_region(struct mm *mm, platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff)
{
  assert(gaddr != 0);

  struct mm_region *region = reinterpret_cast<struct mm_region *>(malloc(sizeof *region));
  region->handle = handle;
  region->haddr = haddr;
  region->gaddr = gaddr;
  region->size = size;
  region->prot = prot;
  region->mm_flags = mm_flags;
  region->mm_fd = mm_fd;
  region->pgoff = pgoff;

  if (RB_INSERT(mm_region_tree, &mm->mm_region_tree, region) != NULL) {
    panic("recording overlapping regions\n");
  }
  struct mm_region *prev = RB_PREV(mm_region_tree, &mm->mm_region_tree, region);
  if (prev == NULL) {
    list_add(&region->list, &mm->mm_regions);
  } else {
    list_add(&region->list, &prev->list);
  }

  return region;
}

bool
is_region_private(struct mm_region *region)
{
  return !(region->mm_flags & LINUX_MAP_SHARED) && region->mm_fd == -1;
}

void
destroy_mm(struct mm *mm)
{
  struct list_head *list, *t;
  list_for_each_safe (list, t, &mm->mm_regions) {
    struct mm_region *r = list_entry(list, struct mm_region, list);
    platform_unmap_mem(r->haddr, r->handle, r->size);
    vm_munmap(r->gaddr, r->size);
    free(r);
  }
  RB_INIT(&mm->mm_region_tree);
  INIT_LIST_HEAD(&mm->mm_regions);
}

bool
addr_ok(gaddr_t addr, int access)
{
  if (addr >= user_addr_max) {
    return false;
  }
  struct mm_region *region = find_region(addr, proc->mm);
  if (!region) {
    return false;
  }
  if (access & ~region->prot) {
    return false;
  }

  return true;
}

size_t
copy_from_user(void *to, gaddr_t src_ptr, size_t n)
{
  while (n > 0) {
    const void *src = guest_to_host(src_ptr);
    if (src == NULL) {
      return n;
    }
    size_t size = MIN(rounddown(src_ptr + 4096, 4096) - src_ptr, n);
    memcpy(to, src, size);
    to = (char *) to + size;
    src_ptr += size;
    n -= size;
  }
  return 0;
}

// On success, returns the length of the string (not including the trailing NUL).
// If access to userspace fails, returns -EFAULT
ssize_t
strncpy_from_user(void *to, gaddr_t src_ptr, size_t n)
{
  size_t len = strnlen_user(src_ptr, n);
  if (len == 0) {
    return -LINUX_EFAULT;
  } else if (n < len) {
    if (copy_from_user(to, src_ptr, n)) {
      return -LINUX_EFAULT;
    }
    return n;
  }
  if (copy_from_user(to, src_ptr, len)) {
    return -LINUX_EFAULT;
  }
  return len - 1;
}

// Get the size of a user string INCLUDING trailing NULL
// On exception, it returns 0. For too long strings, returns a number greater than n.
ssize_t
strnlen_user(gaddr_t src_ptr, size_t n)
{
  int len = 0;
  while ((ssize_t) n > 0) {
    const void *str = guest_to_host(src_ptr);
    if (str == NULL) {
      return 0;
    }
    size_t size = MIN(rounddown(src_ptr + 4096, 4096) - src_ptr, n);
    size_t i = strnlen(reinterpret_cast<const char *>(str), size);
    if (i < size) {
      return len + i + 1;
    }
    assert(i == size);
    len += size;
    src_ptr += size;
    n -= size;
  }
  return len + 1;
}

size_t
copy_to_user(gaddr_t to_ptr, const void *src, size_t n)
{
  while (n > 0) {
    void *to = guest_to_host(to_ptr);
    if (to == NULL) {
      return n;
    }
    size_t size = MIN(rounddown(to_ptr + 4096, 4096) - to_ptr, n);
    memcpy(to, src, size);
    to_ptr += size;
    src = (char *) src + size;
    n -= size;
  }
  return 0;
}

