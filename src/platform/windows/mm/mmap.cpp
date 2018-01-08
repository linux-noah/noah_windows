
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
platform_map_mem(void **ret, platform_handle_t *handle, size_t size, int prot, int platform_mflags)
{
  if (size == 0) {
    return -LINUX_EINVAL;
  }
  if (!(prot & PROT_READ)) {
    return -LINUX_EINVAL;
  }

  SECURITY_ATTRIBUTES sec;
  sec.nLength = sizeof(SECURITY_ATTRIBUTES);
  sec.lpSecurityDescriptor = NULL;
  sec.bInheritHandle = (platform_mflags & MAP_INHERIT) != 0;
  int err;
  HANDLE m = CreateFileMapping(INVALID_HANDLE_VALUE, &sec, generic_to_page_prot(prot, false),
    static_cast<unsigned long>(size >> 32), static_cast<unsigned long>(size), NULL);
  if (m == INVALID_HANDLE_VALUE) {
    return -LINUX_ENOMEM;
  }
  *handle = m;

  *ret = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, size);
  if (*ret == NULL) {
    err = -native_to_linux_errno(errno);
    CloseHandle(m);
  } else {
    err = size;
  }

  return err;
}


int
platform_alloc_filemapping(void **ret, platform_handle_t *handle, ssize_t size, int prot, int platform_mflags, off_t offset, const char *path)
{
  if (size == 0) {
    return -LINUX_EINVAL;
  }
  if (!(prot & PROT_READ)) {
    return -LINUX_EINVAL;
  }
  if (!(platform_mflags & MAP_FILE_PRIVATE) && !(platform_mflags & MAP_FILE_SHARED)) {
    return -LINUX_EINVAL;
  }

  SECURITY_ATTRIBUTES sec;
  sec.nLength = sizeof(SECURITY_ATTRIBUTES);
  sec.lpSecurityDescriptor = NULL;
  sec.bInheritHandle = (platform_mflags & MAP_INHERIT) != 0;
  int err;
  HANDLE f = CreateFile(path, prot, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS, &sec);
  if (f == INVALID_HANDLE_VALUE) {
    err = -native_to_linux_errno(_doserrno);
    goto out_close_file;
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
  HANDLE m = CreateFileMapping(f, NULL, generic_to_page_prot(prot, (platform_mflags & MAP_FILE_SHARED) != 0), size_high, size_low, NULL);
  if (m == INVALID_HANDLE_VALUE) {
    goto out_close_file;
  }
  *handle = m;

  assert(size_high == 0); // TODO
  int w_acc;
  if (prot & PROT_WRITE) {
    if (platform_mflags & MAP_FILE_SHARED) {
      w_acc = FILE_MAP_ALL_ACCESS;
    } else {
      w_acc = FILE_MAP_COPY;
    }
  } else {
    w_acc = FILE_MAP_READ;
  }
  *ret = MapViewOfFile(m, w_acc, 0, offset, size_low);
  if (*ret == NULL) {
    err = -native_to_linux_errno(_doserrno);
    CloseHandle(m);
    goto out_close_file;
  }

  err = size; // Success

out_close_file:
  CloseHandle(f);

  return err;
}

int
platform_unmap_mem(void *mem, platform_handle_t handle, size_t size)
{
  // TODO
  return 0;
}

int
platform_free_filemapping(void *addr, platform_handle_t handle, size_t size)
{
  // TODO:
  return 0;
}
