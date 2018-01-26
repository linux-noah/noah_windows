#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <boost/interprocess/managed_external_buffer.hpp>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <cstring>
#endif

#include "cross_platform.h"
#include "common.h"
#include "util/list.h"
#include "vm.h"
#include "noah.h"
#include "mm.h"

#include "linux/mman.h"

#include "x86/vm.h"
#include "x86/specialreg.h"

namespace bip = boost::interprocess;


const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

gaddr_t
kmap(void *ptr, platform_handle_t handle, size_t size, int flags)
{
  assert((size & 0xfff) == 0);
  assert(((uint64_t) ptr & 0xfff) == 0);

  scoped_lock lock(vkern->mm->mutex);

  record_region(vkern->mm.get(), handle, ptr, vkern->mm->current_brk, size, native_to_linux_mprot(flags), -1, -1, 0);
  vm_mmap(vkern->mm->current_brk, size, flags, ptr);
  vkern->mm->current_brk += size;

  return vkern->mm->current_brk - size;
}

TYPEDEF_PAGE_ALIGNED(uint64_t) pe_t[NR_PAGE_ENTRY];

void
init_page()
{
  pe_t *pml4;
  pe_t *pdp;
  gaddr_t pdp_addr;

  vkern->mm->pml4_addr = kalloc_aligned(&pml4, PROT_READ | PROT_WRITE);
  pdp_addr = kalloc_aligned(&pdp, PROT_READ | PROT_WRITE);
  
  // Straight mapping
  (*pml4)[0] = (pdp_addr & 0x000ffffffffff000ul) | PTE_U | PTE_W | PTE_P;
  for (int i = 0; i < NR_PAGE_ENTRY; i++) {
    (*pdp)[i] = (0x40000000ULL * i) | PTE_PS | PTE_U | PTE_W | PTE_P;
  }
  (*pdp)[NR_PAGE_ENTRY - 1] &= ~PTE_U; // the region that kmap manages

  write_register(VMM_X64_CR0, CR0_PG | CR0_PE | CR0_NE);
  write_register(VMM_X64_CR3, vkern->mm->pml4_addr);
}

TYPEDEF_PAGE_ALIGNED(uint64_t) gdt_t[3];

void
init_segment()
{
  gdt_t *gdt;
  vkern->mm->gdt_addr = kalloc_aligned(&gdt, PROT_READ | PROT_WRITE, PAGE_SIZE(PAGE_4KB), PAGE_SIZE(PAGE_4KB));
  (*gdt)[SEG_NULL] = 0;
  (*gdt)[SEG_CODE] = 0x0020980000000000;
  (*gdt)[SEG_DATA] = 0x0000900000000000;

  write_register(VMM_X64_GDT_BASE, vkern->mm->gdt_addr);
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

mm::mm(bool is_global) :
  is_global(is_global),
  regions(mm::regions_t(mm::regions_key_less(), *vkern->shm_allocator))
{}

mm::~mm()
{
  for (auto cur : regions) {
    auto r = cur.second.get();
    // TODO: unmap handles in mm_region
    vm_munmap(r->gaddr, r->size);
    vkern_shm->destroy_ptr<mm_region>(r);
  }
}

vkern_mm::vkern_mm() :
  mm(true)
{
  start_brk = user_addr_max;
  current_brk = user_addr_max;
}

void init_mmap(struct proc_mm *mm);

proc_mm::proc_mm()
{
  init_mmap(this);
}

void
restore_mm(struct mm *mm)
{
  for (auto &entry : mm->regions) {
    struct mm_region *mm_region = entry.second.get();
    mm_region->haddr = PLATFORM_INVALID_HANDLE;
    // Map the region from the inherited handles
    if (mm_region->is_global) {
      vm_mmap(mm_region->gaddr, mm_region->size, linux_to_native_mprot(mm_region->prot), mm_region->haddr_offset.get());
    } else {
      for (auto &cur_map : mm_region->host_fmappings) {
        auto &range = cur_map.first;
        auto &haddr = cur_map.second.first;
#ifdef _WIN32
        auto &flmap = cur_map.second.second;
        int n_prot = linux_to_native_mprot(mm_region->prot) & ~(PROT_EXEC);
        int err = platform_restore_mapped_mem(&haddr, flmap->handle, mm_region->size, n_prot, MAP_FILE_PRIVATE | MAP_INHERIT);
        assert(err >= 0);
#endif
        // TODO: Separate CreateFileMapping and MapViewOfFile in restoring
        // TODO: Make it read-only for CoW
        vm_mmap(
          mm_region->gaddr + range.first - mm_region->pgoff,
          range.second - range.first,
          linux_to_native_mprot(mm_region->prot & ~(LINUX_PROT_WRITE)),
          reinterpret_cast<char *>(haddr) + range.first
        );
      }
    }
  }
}

void
clone_mm(struct mm *dst_mm, struct mm *src_mm)
{
  sharable_lock lock(src_mm->mutex);

  // TODO: make them read-only for CoW
  dst_mm->is_global = src_mm->is_global;
  dst_mm->start_brk = src_mm->start_brk;
  dst_mm->current_brk = src_mm->current_brk;
  for (auto &cur : src_mm->regions) {
    auto &key = cur.first;
    auto &reg = cur.second;
    if (reg->prot & LINUX_PROT_WRITE)
      reg->should_cow = true;
    auto cloned_reg = vkern_shm->construct<struct mm_region>(bip::anonymous_instance)(*reg);
    cloned_reg->cow_handle = decltype(cloned_reg->cow_handle)();
    dst_mm->regions.emplace(key, offset_ptr<struct mm_region>(cloned_reg));
    for (auto &cur_map : reg->host_fmappings) {
      auto &range = cur_map.first;
      auto &haddr = cur_map.second.first;
      auto &flmap = cur_map.second.second;
      flmap->map(range);
      cloned_reg->host_fmappings.emplace(
        range,
        host_fmappings_t::val_t(
          haddr,
          shared_ptr<host_filemap_handle>(flmap)
        )
      );
      vm_mmap(reg->gaddr + range.first - reg->pgoff, range.second - range.first, linux_to_native_mprot(reg->prot) & ~PROT_WRITE, haddr);
    }
  }
}

void *
guest_to_host(gaddr_t gaddr)
{
  struct mm_region *region = find_region(gaddr, proc->mm.get());
  if (!region) {
    region = find_region(gaddr, vkern->mm.get());
  }
  if (!region) {
    return NULL;
  }
  return (char *)mm_region_haddr(region, gaddr);
}

uint 
range_refcount::incref(range_t range)
{
  auto found = find(range);
  int cnt;
  if (found == end()) {
    cnt = 1;
  } else {
    cnt = found->second;
  }
  set_range(range, cnt + 1);
  return cnt;
}

uint 
range_refcount::decref(range_t range)
{
  auto found = find(range);
  assert(found != end());
  auto &cnt = found->second;
  set_range(range, cnt - 1);
  return cnt;
}

uint
host_filemap_handle::map(range_t range) 
{
  scoped_lock lock(map_mutex);
  return map_refcount.incref(range);
}

uint 
host_filemap_handle::unmap(range_t range) 
{
  scoped_lock lock(map_mutex);
  return map_refcount.decref(range);
};


mm_region::mm_region(platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff, bool is_global, bool should_cow) :
  haddr(haddr),
  haddr_offset(offset_ptr<void>(haddr)),
  gaddr(gaddr),
  size(size),
  prot(prot),
  mm_flags(mm_flags),
  mm_fd(mm_fd),
  pgoff(pgoff),
  is_global(is_global),
  should_cow(should_cow)
{
  auto flmap_handle = vkern_shm->construct<host_filemap_handle>(bip::anonymous_instance)(handle, size);
  flmap_handle->map(host_filemap_handle::range_t(pgoff, pgoff + size));
  host_fmappings.emplace(
    host_fmappings_t::range_t(pgoff, pgoff + size),
    host_fmappings_t::val_t(
      haddr,
      shared_ptr<host_filemap_handle>(
        flmap_handle,
        extbuf_allocator_t<offset_ptr<void>>(vkern_shm->get_segment_manager()),
        extbuf_deleter_t<host_filemap_handle>(vkern_shm->get_segment_manager())
      )
    )
  );
}

mm_region::mm_region(platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff, bool is_global) :
  mm_region(handle, haddr, gaddr, size, prot, mm_flags, mm_fd, pgoff, is_global, false)
{}

int
region_compare(const struct mm_region *r1, const struct mm_region *r2)
{
  if (r1->gaddr >= r2->gaddr + r2->size) {
    return 1;
  }
  if (r1->gaddr + r1->size <= r2->gaddr) {
    return -1;
  }
  
  return 0;
}

struct mm_region*
/* Look up the mm_region which gaddr in [mm_region->gaddr, +size) */
find_region(gaddr_t gaddr, struct mm *mm)
{
  auto find = mm->regions.find(mm::regions_key_t(gaddr, gaddr + 1));
  if (find != mm->regions.end()) {
    return find->second.get();
  }
  return nullptr;
}

pair<mm::regions_iter_t, mm::regions_iter_t>
find_region_range(gaddr_t gaddr, size_t size, struct mm *mm)
{
  return mm->regions.equal_range(mm::regions_key_t(gaddr, gaddr + size));
}

pair<mm_region *, mm_region *>
split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr)
{
  // TODO: not tested yet! split_region is called by only unmap, and unmap is not being called now
  assert(is_page_aligned((void*)gaddr, PAGE_4KB));

  auto tail = vkern_shm->construct<mm_region>(bip::anonymous_instance)(*region);
  auto offset = gaddr - region->gaddr;
  tail->size = region->size - offset;
  tail->pgoff = region->pgoff + offset;
  region->size = offset;
  // TODO: modify mm_regions of mm

  auto head_range = host_fmappings_t::range_t(region->pgoff, region->pgoff + region->size);
  auto tail_range = host_fmappings_t::range_t(tail->pgoff, tail->pgoff + tail->size);
  region->host_fmappings.erase_range(tail_range);
  tail->host_fmappings.erase_range(head_range);
  return pair<mm_region *, mm_region *>(region, tail);
}

struct mm_region*
record_region(struct mm *mm, platform_handle_t handle, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff)
{
  assert(gaddr != 0);

  auto region = vkern_shm->construct<mm_region>(bip::anonymous_instance)
                                               (handle, haddr, gaddr, size,
                                                prot, mm_flags, mm_fd, pgoff,
                                                mm->is_global);
  auto inserted = mm->regions.emplace(mm::regions_key_t(gaddr, gaddr + size), offset_ptr<mm_region>(region));
  if (!inserted.second) {
    panic("recording overlapping regions\n");
  }

  return region;
}

bool
is_region_private(struct mm_region *region)
{
  return !(region->mm_flags & LINUX_MAP_SHARED) && region->mm_fd == -1;
}

void *
mm_region_haddr(struct mm_region *region, gaddr_t gaddr)
{
  if (region->is_global) {
    return reinterpret_cast<char *>(region->haddr_offset.get()) + gaddr;
  } else {
    auto offset_inhandle = gaddr - region->gaddr + region->pgoff;
    auto find = region->host_fmappings.find(host_fmappings_t::range_t(offset_inhandle, offset_inhandle + 1));
    auto debug0 = find->first;
    auto debug1 = find->second;
    return reinterpret_cast<char *>(find->second.first) + offset_inhandle;
  }
}

// Note: The caller should have the lock of mm
void
handle_cow(struct mm *mm, struct mm_region *region, gaddr_t gaddr, size_t size, uint64_t data)
{
#ifdef _WIN32
  auto offset_inhandle = gaddr - region->gaddr + region->pgoff;
  auto cow_range_inhandle = host_filemap_handle::range_t(rounddown(offset_inhandle, PAGE_SIZE(PAGE_4KB)), roundup(offset_inhandle, PAGE_SIZE(PAGE_4KB)));
  auto cow_pgoff = gaddr % PAGE_SIZE(PAGE_4KB);
  assert(offset_inhandle + size <= cow_range_inhandle.second); // TODO: case where the page boundary is crossed

  auto find = region->host_fmappings.find(cow_range_inhandle);
  auto &flmap = find->second.second;
  auto old_page = reinterpret_cast<char *>(find->second.first) + cow_range_inhandle.first;
  if (find->second.second == region->cow_handle) {
    // CoW of this page is already done. Just one of continuing mmio operations.
    memcpy(old_page + offset_inhandle, &data, size);
    return;
  }
  auto refcount = flmap->unmap(cow_range_inhandle);
  if (refcount == 1) {
    flmap->map(cow_range_inhandle);
    vm_mmap(rounddown(gaddr, PAGE_SIZE(PAGE_4KB)), PAGE_SIZE(PAGE_4KB), linux_to_native_mprot(region->prot), old_page);
    memcpy(old_page + cow_pgoff, &data, size);
    return;
  }
  if (!region->cow_handle) {
    platform_handle_t handle;
    platform_map_mem(&region->haddr, &handle, region->size + region->pgoff, linux_to_native_mprot(region->prot), MAP_FILE_SHARED | MAP_INHERIT | MAP_RESERVE);
    region->cow_handle = std::move(shared_ptr<host_filemap_handle>(
      vkern_shm->construct<host_filemap_handle>(bip::anonymous_instance)(handle, region->size + region->pgoff),
      extbuf_allocator_t<offset_ptr<void>>(vkern_shm->get_segment_manager()),
      extbuf_deleter_t<host_filemap_handle>(vkern_shm->get_segment_manager())
    ));
  }
  auto new_page = reinterpret_cast<char *>(region->haddr) + cow_range_inhandle.first;
  vm_mmap(rounddown(gaddr, PAGE_SIZE(PAGE_4KB)), PAGE_SIZE(PAGE_4KB), linux_to_native_mprot(region->prot), new_page); // The memory region is committed by vm_mmap
  memcpy(new_page, old_page, PAGE_SIZE(PAGE_4KB));
  memcpy(new_page + cow_pgoff, &data, size);
  region->cow_handle->map(cow_range_inhandle);
  /*
  // Debug
  auto hfm = region->host_fmappings;
  for (auto &cur : hfm) {
    printf("[%x, %x) : (host:%x, shared_ptr has: %x, count: %d)\n", cur.first.first, cur.first.second, cur.second.first, cur.second.second.get(), cur.second.second.use_count());
  }
  */
  region->host_fmappings.set_range(cow_range_inhandle, host_fmappings_t::val_t(region->haddr, region->cow_handle));
#endif
}

bool
addr_ok(gaddr_t addr, int access)
{
  if (addr >= user_addr_max) {
    return false;
  }
  struct mm_region *region = find_region(addr, proc->mm.get());
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

