
#include <cerrno>
#include <Windows.h>
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

extern "C" {
#include "linux/errno.h"
#include "linux/mman.h"
#include "mm.h"
}

namespace bi = boost::interprocess;

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
  bi::mode_t mode = bi::read_only;
  if (prot == PROT_READ) mode = bi::read_only;
  if (prot & PROT_WRITE) {
    if (writes_back) {
      mode = bi::read_write;
    } else {
      mode = bi::copy_on_write;
    }
  }

  try {
    bi::file_mapping mapping(path, mode);
    bi::mapped_region region;
    if (size == -1) {
      region = bi::mapped_region(mapping, mode, offset);
      size = region.get_size();
    } else {
      region = bi::mapped_region(mapping, mode, offset);
    }
    *ret = region.get_address();
  } catch (const bi::interprocess_exception &e) {
    // TODO: neat error conversion
    return -LINUX_ENOENT;
  } catch (...) {
    return -LINUX_ENOENT;
  }
  return size;
}

int
platform_unmap_mem(void *mem, size_t size)
{
  // TODO: unmap of filemapped memory
  if (!VirtualFree(mem, size, MEM_DECOMMIT)) {
    return -native_to_linux_errno(_doserrno);
  }
  return 0;
}
