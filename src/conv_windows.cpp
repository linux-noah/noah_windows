extern "C" {
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "cross_platform.h"
#include "common.h"
#include "noah.h"
#include "mm.h"

  int
  native_to_linux_mprot(int win_mprot)
  {
    int linux_prot = 0;
    if (win_mprot & PROT_READ)
      linux_prot |= LINUX_PROT_READ;
    if (win_mprot & PROT_WRITE)
      linux_prot |= LINUX_PROT_WRITE;
    if (win_mprot & PROT_EXEC)
      linux_prot |= LINUX_PROT_EXEC;
    return linux_prot;
  }

  int
  linux_to_native_mprot(int linux_prot)
  {
    int darwin_prot = 0;
    if (linux_prot & LINUX_PROT_READ)
      darwin_prot |= PROT_READ;
    if (linux_prot & LINUX_PROT_WRITE)
      darwin_prot |= PROT_WRITE;
    if (linux_prot & LINUX_PROT_EXEC)
      darwin_prot |= PROT_EXEC;
    return darwin_prot;
  }

  int
  linux_to_native_errno(int linux_errno)
  {
    switch (linux_errno) {
    case LINUX_EPERM:            return EPERM;
    case LINUX_ENOENT:           return ENOENT;
    case LINUX_ESRCH:            return ESRCH;
    case LINUX_EINTR:            return EINTR;
    case LINUX_EIO:              return EIO;
    case LINUX_ENXIO:            return ENXIO;
    case LINUX_E2BIG:            return E2BIG;
    case LINUX_ENOEXEC:          return ENOEXEC;
    case LINUX_EBADF:            return EBADF;
    case LINUX_ECHILD:           return ECHILD;
    case LINUX_EAGAIN:           return EAGAIN;
    case LINUX_ENOMEM:           return ENOMEM;
    case LINUX_EACCES:           return EACCES;
    case LINUX_EFAULT:           return EFAULT;
    case LINUX_EBUSY:            return EBUSY;
    case LINUX_EEXIST:           return EEXIST;
    case LINUX_EXDEV:            return EXDEV;
    case LINUX_ENODEV:           return ENODEV;
    case LINUX_ENOTDIR:          return ENOTDIR;
    case LINUX_EISDIR:           return EISDIR;
    case LINUX_EINVAL:           return EINVAL;
    case LINUX_ENFILE:           return ENFILE;
    case LINUX_EMFILE:           return EMFILE;
    case LINUX_ENOTTY:           return ENOTTY;
    case LINUX_ETXTBSY:          return ETXTBSY;
    case LINUX_EFBIG:            return EFBIG;
    case LINUX_ENOSPC:           return ENOSPC;
    case LINUX_ESPIPE:           return ESPIPE;
    case LINUX_EROFS:            return EROFS;
    case LINUX_EMLINK:           return EMLINK;
    case LINUX_EPIPE:            return EPIPE;
    case LINUX_EDOM:             return EDOM;
    case LINUX_ERANGE:           return ERANGE;
    case LINUX_EDEADLK:          return EDEADLK;
    case LINUX_ENAMETOOLONG:     return ENAMETOOLONG;
    case LINUX_ENOLCK:           return ENOLCK;
    case LINUX_ENOSYS:           return ENOSYS;
    case LINUX_ENOTEMPTY:        return ENOTEMPTY;
    case LINUX_ELOOP:            return ELOOP;
    case LINUX_ENOMSG:           return ENOMSG;
    case LINUX_EIDRM:            return EIDRM;
    case LINUX_ENOSTR:           return ENOSTR;
    case LINUX_ENODATA:          return ENODATA;
    case LINUX_ETIME:            return ETIME;
    case LINUX_ENOSR:            return ENOSR;
    case LINUX_ENOLINK:          return ENOLINK;
    case LINUX_EPROTO:           return EPROTO;
    case LINUX_EBADMSG:          return EBADMSG;
    case LINUX_EOVERFLOW:        return EOVERFLOW;
    case LINUX_EILSEQ:           return EILSEQ;
    case LINUX_ENOTSOCK:         return ENOTSOCK;
    case LINUX_EDESTADDRREQ:     return EDESTADDRREQ;
    case LINUX_EMSGSIZE:         return EMSGSIZE;
    case LINUX_EPROTOTYPE:       return EPROTOTYPE;
    case LINUX_ENOPROTOOPT:      return ENOPROTOOPT;
    case LINUX_EPROTONOSUPPORT:  return EPROTONOSUPPORT;
    case LINUX_EOPNOTSUPP:       return EOPNOTSUPP;
    case LINUX_EAFNOSUPPORT:     return EAFNOSUPPORT;
    case LINUX_EADDRINUSE:       return EADDRINUSE;
    case LINUX_EADDRNOTAVAIL:    return EADDRNOTAVAIL;
    case LINUX_ENETDOWN:         return ENETDOWN;
    case LINUX_ENETUNREACH:      return ENETUNREACH;
    case LINUX_ENETRESET:        return ENETRESET;
    case LINUX_ECONNABORTED:     return ECONNABORTED;
    case LINUX_ECONNRESET:       return ECONNRESET;
    case LINUX_ENOBUFS:          return ENOBUFS;
    case LINUX_EISCONN:          return EISCONN;
    case LINUX_ENOTCONN:         return ENOTCONN;
    case LINUX_ETIMEDOUT:        return ETIMEDOUT;
    case LINUX_ECONNREFUSED:     return ECONNREFUSED;
    case LINUX_EHOSTUNREACH:     return EHOSTUNREACH;
    case LINUX_EALREADY:         return EALREADY;
    case LINUX_EINPROGRESS:      return EINPROGRESS;
    case LINUX_ECANCELED:        return ECANCELED;
    case LINUX_EOWNERDEAD:       return EOWNERDEAD;
    case LINUX_ENOTRECOVERABLE:  return ENOTRECOVERABLE;
    default:
      return EOTHER;
    }
  }

  int
  native_to_linux_errno(int darwin_errno)
  {
    switch (darwin_errno) {
    case EPERM:            return LINUX_EPERM;
    case ENOENT:           return LINUX_ENOENT;
    case ESRCH:            return LINUX_ESRCH;
    case EINTR:            return LINUX_EINTR;
    case EIO:              return LINUX_EIO;
    case ENXIO:            return LINUX_ENXIO;
    case E2BIG:            return LINUX_E2BIG;
    case ENOEXEC:          return LINUX_ENOEXEC;
    case EBADF:            return LINUX_EBADF;
    case ECHILD:           return LINUX_ECHILD;
    case EAGAIN:           return LINUX_EAGAIN;
    case ENOMEM:           return LINUX_ENOMEM;
    case EACCES:           return LINUX_EACCES;
    case EFAULT:           return LINUX_EFAULT;
    case EBUSY:            return LINUX_EBUSY;
    case EEXIST:           return LINUX_EEXIST;
    case EXDEV:            return LINUX_EXDEV;
    case ENODEV:           return LINUX_ENODEV;
    case ENOTDIR:          return LINUX_ENOTDIR;
    case EISDIR:           return LINUX_EISDIR;
    case EINVAL:           return LINUX_EINVAL;
    case ENFILE:           return LINUX_ENFILE;
    case EMFILE:           return LINUX_EMFILE;
    case ENOTTY:           return LINUX_ENOTTY;
    case ETXTBSY:          return LINUX_ETXTBSY;
    case EFBIG:            return LINUX_EFBIG;
    case ENOSPC:           return LINUX_ENOSPC;
    case ESPIPE:           return LINUX_ESPIPE;
    case EROFS:            return LINUX_EROFS;
    case EMLINK:           return LINUX_EMLINK;
    case EPIPE:            return LINUX_EPIPE;
    case EDOM:             return LINUX_EDOM;
    case ERANGE:           return LINUX_ERANGE;
    case EDEADLK:          return LINUX_EDEADLK;
    case ENAMETOOLONG:     return LINUX_ENAMETOOLONG;
    case ENOLCK:           return LINUX_ENOLCK;
    case ENOSYS:           return LINUX_ENOSYS;
    case ENOTEMPTY:        return LINUX_ENOTEMPTY;
    case ELOOP:            return LINUX_ELOOP;
    case ENOMSG:           return LINUX_ENOMSG;
    case EIDRM:            return LINUX_EIDRM;
    case ENOSTR:           return LINUX_ENOSTR;
    case ENODATA:          return LINUX_ENODATA;
    case ETIME:            return LINUX_ETIME;
    case ENOSR:            return LINUX_ENOSR;
    case ENOLINK:          return LINUX_ENOLINK;
    case EPROTO:           return LINUX_EPROTO;
    case EBADMSG:          return LINUX_EBADMSG;
    case EOVERFLOW:        return LINUX_EOVERFLOW;
    case EILSEQ:           return LINUX_EILSEQ;
    case ENOTSOCK:         return LINUX_ENOTSOCK;
    case EDESTADDRREQ:     return LINUX_EDESTADDRREQ;
    case EMSGSIZE:         return LINUX_EMSGSIZE;
    case EPROTOTYPE:       return LINUX_EPROTOTYPE;
    case ENOPROTOOPT:      return LINUX_ENOPROTOOPT;
    case EPROTONOSUPPORT:  return LINUX_EPROTONOSUPPORT;
    case EOPNOTSUPP:       return LINUX_EOPNOTSUPP;
    case EAFNOSUPPORT:     return LINUX_EAFNOSUPPORT;
    case EADDRINUSE:       return LINUX_EADDRINUSE;
    case EADDRNOTAVAIL:    return LINUX_EADDRNOTAVAIL;
    case ENETDOWN:         return LINUX_ENETDOWN;
    case ENETUNREACH:      return LINUX_ENETUNREACH;
    case ENETRESET:        return LINUX_ENETRESET;
    case ECONNABORTED:     return LINUX_ECONNABORTED;
    case ECONNRESET:       return LINUX_ECONNRESET;
    case ENOBUFS:          return LINUX_ENOBUFS;
    case EISCONN:          return LINUX_EISCONN;
    case ENOTCONN:         return LINUX_ENOTCONN;
    case ETIMEDOUT:        return LINUX_ETIMEDOUT;
    case ECONNREFUSED:     return LINUX_ECONNREFUSED;
    case EHOSTUNREACH:     return LINUX_EHOSTUNREACH;
    case EALREADY:         return LINUX_EALREADY;
    case EINPROGRESS:      return LINUX_EINPROGRESS;
    case ECANCELED:        return LINUX_ECANCELED;
    case EOWNERDEAD:       return LINUX_EOWNERDEAD;
    case ENOTRECOVERABLE:  return LINUX_ENOTRECOVERABLE;
    default:
      assert(false);
    }
  }

}
