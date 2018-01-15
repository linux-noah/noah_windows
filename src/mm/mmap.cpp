#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <cerrno>
#include <fcntl.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#ifdef __APPLE__
#include <Hypervisor/hv.h>
#endif
#endif

#include "common.h"

#include "noah.h"
#include "vm.h"
#include "mm.h"
#include "x86/vm.h"

#include "linux/mman.h"

void
init_mmap(struct proc_mm *mm)
{
  mm->current_mmap_top = 0x00000000c0000000;
}

gaddr_t
alloc_region(size_t len)
{
  len = roundup(len, PAGE_SIZE(PAGE_4KB));
  proc->mm->current_mmap_top += len;
  return proc->mm->current_mmap_top - len;
}

int
do_munmap(gaddr_t gaddr, size_t size)
{
  if (!is_page_aligned((void*)gaddr, PAGE_4KB)) {
    return -LINUX_EINVAL;
  }
  size = roundup(size, PAGE_SIZE(PAGE_4KB)); // Linux kernel also does this

  // NOTE: TODO: Not tested yet!!
  auto overlap_iter = find_region_range(gaddr, size, proc->mm.get());
  if (overlap_iter.first == overlap_iter.second) {
    return -LINUX_ENOMEM;
  }
  
  while (overlap_iter.first != overlap_iter.second) {
    auto cur = overlap_iter.first++;
    auto overlapping = cur->second.get();

    if (overlapping->gaddr < gaddr) {
      overlapping = split_region(proc->mm.get(), overlapping, gaddr).second;
    }
    if (overlapping->gaddr + overlapping->size > gaddr + size) {
      overlapping = split_region(proc->mm.get(), overlapping, gaddr + size).first;
    }
    proc->mm->mm_regions->erase(mm::mm_regions_key_t(overlapping->gaddr, overlapping->gaddr + overlapping->size));
    vm_munmap(overlapping->gaddr, overlapping->size);
    platform_unmap_mem(mm_region_haddr(overlapping), overlapping->handle, overlapping->size);
    vkern_shm->destroy_ptr<mm_region>(cur->second.get());
  }

  return 0;
}

gaddr_t
do_mmap(gaddr_t addr, size_t len, int n_prot, int l_prot, int l_flags, int fd, off_t offset)
{
  assert((addr & 0xfff) == 0);
  if (!(l_flags & LINUX_MAP_PRIVATE) && !(l_flags & LINUX_MAP_ANON)) {
    return -LINUX_EINVAL;
  }

  /* some l_flags are obsolete and just ignored */
  l_flags &= ~LINUX_MAP_DENYWRITE;
  l_flags &= ~LINUX_MAP_EXECUTABLE;

  /* We ignore these currenlty */
  l_flags &= ~LINUX_MAP_NORESERVE;

  /* the linux kernel does nothing for LINUX_MAP_STACK */
  l_flags &= ~LINUX_MAP_STACK;

  len = roundup(len, PAGE_SIZE(PAGE_4KB));

  if ((l_flags & ~(LINUX_MAP_SHARED | LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANON)) != 0) {
    warnk("unsupported mmap l_flags: 0x%x\n", l_flags);
    exit(1);
  }
  if (l_flags & LINUX_MAP_ANON) {
    fd = -1;
    offset = 0;
  }
  if ((l_flags & LINUX_MAP_FIXED) == 0) {
    addr = alloc_region(len);
  }

  void *ptr;
  platform_handle_t handle;
  int err;
  if (!(l_flags & LINUX_MAP_ANON)) {
    // TODO
    return -LINUX_EINVAL;
  } else {
    err = platform_map_mem(&ptr, &handle, len, n_prot, linux_to_native_mflags(l_flags));
  }
  if (err < 0) {
    panic("mmap failed. addr :0x%llx, len: 0x%lux, prot: %d, l_flags: %d, fd: %d, offset: 0x%llx\n", addr, len, l_prot, l_flags, fd, offset);
  }

  do_munmap(addr, len);
  record_region(proc->mm.get(), handle, ptr, addr, len, l_prot, l_flags, fd, offset);

  vm_mmap(addr, len, linux_to_native_mprot(l_prot), ptr);

  return addr;
}
