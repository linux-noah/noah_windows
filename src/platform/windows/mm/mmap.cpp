
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
generic_to_page_prot(int prot, bool cow)
{
  int w_prot;
  if (prot & PROT_WRITE) {
    if (cow) {
      w_prot = PAGE_WRITECOPY;
    } else {
      w_prot = PAGE_READWRITE;
    }
  } else {
    w_prot = PAGE_READONLY;
  }
  if (prot & PROT_EXEC) {
    w_prot <<= 4;
  }
  return w_prot;
}

int
platform_map_mem(void **ret, size_t size, int prot)
{
  *ret = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, generic_to_page_prot(prot, false));
  if (*ret == NULL) {
    return -native_to_linux_errno(_doserrno);
  }
  return size;
}

int
platform_map_shared_mem(void **ret, size_t size, int prot)
{
  return -LINUX_EINVAL;
}

int
platform_alloc_filemapping(void **ret, ssize_t size, int prot, bool writes_back, off_t offset, const char *path)
{
  if (size == 0) {
    return -LINUX_EINVAL;
  }
  if (!(prot & PROT_READ)) {
    return -LINUX_EINVAL;
  }

  int err;
  HANDLE f = CreateFile(path, prot, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS, NULL);
  if (f == INVALID_HANDLE_VALUE) {
    err = -native_to_linux_errno(_doserrno);
    goto out_close_file;
  }

  int w_acc;
  if (prot & PROT_WRITE) {
    if (writes_back) {
      w_acc = FILE_MAP_ALL_ACCESS;
    } else {
      w_acc = FILE_MAP_COPY;
    }
  } else {
    w_acc = FILE_MAP_READ;
  }
  DWORD size_high, size_low;
  if (size == -1) { // Treat as equivalent to the file size
    size_low = GetFileSize(f, &size_high);
    if (size_low == INVALID_FILE_SIZE) {
      err = -native_to_linux_errno(_doserrno);
      goto out_close_file;
    }
    size = (size_high << 32) | size_low;
  }
  HANDLE m = CreateFileMapping(f, NULL, generic_to_page_prot(prot, !writes_back), size_high, size_low, NULL);
  if (m == INVALID_HANDLE_VALUE) {
    goto out_close_mapping;
  }

  assert(size_high == 0); // TODO
  *ret = MapViewOfFile(m, w_acc, 0, offset, size_low);
  if (*ret == NULL) {
    err = -native_to_linux_errno(_doserrno);
    goto out_close_mapping;
  }

  err = size; // Success

out_close_mapping:
  CloseHandle(m);
out_close_file:
  CloseHandle(f);

  return err;
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

int
platform_free_filemapping(void *mem, size_t size)
{
  // TODO:
  return 0;
}
