
#include <cerrno>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "linux/errno.h"
#include "linux/mman.h"
#include "mm.h"

int
platform_map_mem(void **ret, platform_handle_t *handle, size_t size, int prot, int platform_mflags)
{
  *ret = mmap(0, size, prot, platform_mflags, -1, 0);
  if (*ret == MAP_FAILED) {
    return -native_to_linux_errno(errno);
  }
  *handle = -1;
  return size;
}

int
platform_alloc_filemapping(void **ret, platform_handle_t *handle, ssize_t size, int prot, int platform_mflags, off_t offset, const char *path)
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

  *ret = mmap(0, size, prot, platform_mflags, fd, offset);
  if (*ret == MAP_FAILED) {
    return -native_to_linux_errno(errno);
  }
  close(fd);

  *handle = -1;
  return size;
}

int
platform_unmap_mem(void *mem, platform_handle_t handle, size_t size)
{
  int ret = munmap(mem, size);
  if (ret < 0) {
    return -native_to_linux_errno(errno);
  }
  return 0;
}

int
platform_free_filemapping(void *addr, platform_handle_t handle, size_t size)
{
  return platform_unmap_mem(addr, handle, size);
}
