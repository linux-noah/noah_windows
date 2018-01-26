#include <cerrno>
#include <Windows.h>
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include "linux/errno.h"
#include "linux/mman.h"
#include "mm.h"

namespace bip = boost::interprocess;

static inline int
prot_to_page_access(int prot, bool cow)
{
  int page_acc;
  if (prot & PROT_WRITE) {
    if (cow) {
      page_acc = PAGE_WRITECOPY;
    } else {
      page_acc = PAGE_READWRITE;
    }
  } else {
    page_acc = PAGE_READONLY;
  }
  if (prot & PROT_EXEC) {
    page_acc <<= 4;
  }
  return page_acc;
}

static inline int
prot_to_filemap_access(int prot, bool cow)
{
  int w_acc = 0;
  if (prot & PROT_WRITE) {
    if (cow) {
      w_acc = FILE_MAP_COPY;
    } else {
      w_acc = FILE_MAP_ALL_ACCESS;
    }
  } else {
    w_acc = FILE_MAP_READ;
  }
  if (prot & PROT_EXEC) {
    w_acc |= FILE_MAP_EXECUTE;
  }
  return w_acc;
}

static inline int
prot_to_generic_access(int prot)
{
  int gen_acc = 0;
  if (prot & PROT_READ)
    gen_acc |= GENERIC_READ;
  if (prot & PROT_WRITE)
    gen_acc |= GENERIC_WRITE;
  if (prot & PROT_EXEC)
    gen_acc |= GENERIC_EXECUTE;
  return gen_acc;
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
  int acc = prot_to_page_access(PROT_READ | PROT_WRITE | PROT_EXEC, false);
  if (platform_mflags & MAP_RESERVE)
    acc |= SEC_RESERVE;
  HANDLE m = CreateFileMapping(INVALID_HANDLE_VALUE, &sec, acc,
    static_cast<unsigned long>(size >> 32), static_cast<unsigned long>(size), NULL);
  if (m == INVALID_HANDLE_VALUE) {
    return -LINUX_ENOMEM;
  }
  *handle = m;

  // HAX seems to fail VM-entry the map view does not have PROT_READ | PROT_WRITE access
  *ret = MapViewOfFile(m, prot_to_filemap_access(PROT_READ | PROT_WRITE, false), 0, 0, size);
  if (*ret == NULL) {
    err = -winnative_to_linux_errno(GetLastError());
    CloseHandle(m);
  } else {
    err = size;
  }

  return err;
}

int
platform_restore_mapped_mem(void **ret, platform_handle_t m, size_t size, int prot, int platform_mflags)
{
  if (size == 0) {
    return -LINUX_EINVAL;
  }
  if (!(prot & PROT_READ)) {
    return -LINUX_EINVAL;
  }

  int err;
  // HAX seems to fail VM-entry the map view does not have PROT_READ | PROT_WRITE access
  *ret = MapViewOfFile(m, prot_to_filemap_access(PROT_READ | PROT_WRITE, false), 0, 0, size);
  if (*ret == NULL) {
    err = -winnative_to_linux_errno(GetLastError());
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
  HANDLE f = CreateFile(path, prot_to_generic_access(prot), FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, FILE_FLAG_POSIX_SEMANTICS, &sec);
  if (f == INVALID_HANDLE_VALUE) {
    err = -winnative_to_linux_errno(GetLastError());
    goto out_close_file;
  }

  DWORD size_high, size_low;
  if (size == -1) { // Treat as equivalent to the file size
    size_low = GetFileSize(f, &size_high);
    if (size_low == INVALID_FILE_SIZE) {
      err = -winnative_to_linux_errno(GetLastError());
      goto out_close_file;
    }
    size = (size_high << 32) | size_low;
  }
  HANDLE m = CreateFileMapping(f, NULL, prot_to_page_access(prot, false), size_high, size_low, NULL);
  if (m == INVALID_HANDLE_VALUE) {
    goto out_close_file;
  }
  *handle = m;

  *ret = MapViewOfFile(m, prot_to_filemap_access(prot, (platform_mflags & MAP_FILE_SHARED) == 0), 0, offset, size_low);
  if (*ret == NULL) {
    err = -winnative_to_linux_errno(GetLastError());
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
