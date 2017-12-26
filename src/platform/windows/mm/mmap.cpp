
#include <cerrno>

extern "C" {
#include "linux/errno.h"
#include "linux/mman.h"
#include "mm.h"
}


int
platform_alloc_mem(void **ret, size_t size, int prot)
{
  *ret = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, prot);
  if (*ret == NULL) {
    return -native_to_linux_errno(_doserrno);
  }
  return size;
}

int
platform_alloc_shared_mem(void **ret, size_t size, int prot)
{
  return -LINUX_EINVAL;
}

int
platform_alloc_filemapped_mem(void **ret, ssize_t size, int prot, bool writes_back, off_t offset, const char *path)
{
  return -LINUX_EINVAL;
}

int
platform_unmap_mem(void *mem, size_t size)
{
  return -LINUX_EINVAL;
}
