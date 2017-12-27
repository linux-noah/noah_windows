
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <stdbool.h>

#include "linux/errno.h"
#include "linux/mman.h"
#include "mm.h"


int
platform_map_mem(void **ret, size_t size, int prot)
{
  *ret = mmap(0, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (*ret == MAP_FAILED) {
    return -native_to_linux_errno(errno);
  }
  return size;
}

int
platform_map_shared_mem(void **ret, size_t size, int prot)
{
  *ret = mmap(0, size, prot, MAP_SHARED, -1, 0);
  if (*ret == MAP_FAILED) {
    return -native_to_linux_errno(errno);
  }
  return size;
}

int
platform_alloc_filemapping(void **ret, ssize_t size, int prot, bool writes_back, off_t offset, const char *path)
{
  // TODO: manage temporary FDs via vkern_open/close
  int fd;
  struct stat st;

  if ((fd = open(path, O_RDONLY, 0)) < 0) {
    return -native_to_linux_errno(errno);
  }

  if (size == -1) {
    fstat(fd, &st);
    size = st.st_size;
  }

  int flags = writes_back ? MAP_SHARED : MAP_PRIVATE;
  *ret = mmap(0, size, prot, flags, fd, offset);
  if (*ret == MAP_FAILED) {
    return -native_to_linux_errno(errno);
  }
  close(fd);

  return size;
}

int
platform_unmap_mem(void *mem, size_t size)
{
  int ret = munmap(mem, size);
  if (ret < 0) {
    return -native_to_linux_errno(errno);
  }
  return 0;
}

int
platform_free_filemapping(void *mem, size_t size)
{
  return platform_unmap_mem(addr, size);
}
