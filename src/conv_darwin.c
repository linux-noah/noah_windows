#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "linux/termios.h"
#include "linux/mman.h"

#include <unistd.h>
#include <termios.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

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
  case LINUX_ENOTBLK:          return ENOTBLK;
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
  case LINUX_ECHRNG:           return ECHRNG;
  case LINUX_EL2NSYNC:         return EL2NSYNC;
  case LINUX_EL3HLT:           return EL3HLT;
  case LINUX_EL3RST:           return EL3RST;
  case LINUX_ELNRNG:           return ELNRNG;
  case LINUX_EUNATCH:          return EUNATCH;
  case LINUX_ENOCSI:           return ENOCSI;
  case LINUX_EL2HLT:           return EL2HLT;
  case LINUX_EBADE:            return EBADE;
  case LINUX_EBADR:            return EBADR;
  case LINUX_EXFULL:           return EXFULL;
  case LINUX_ENOANO:           return ENOANO;
  case LINUX_EBADRQC:          return EBADRQC;
  case LINUX_EBADSLT:          return EBADSLT;
  case LINUX_EBFONT:           return EBFONT;
  case LINUX_ENOSTR:           return ENOSTR;
  case LINUX_ENODATA:          return ENODATA;
  case LINUX_ETIME:            return ETIME;
  case LINUX_ENOSR:            return ENOSR;
  case LINUX_ENONET:           return ENONET;
  case LINUX_ENOPKG:           return ENOPKG;
  case LINUX_EREMOTE:          return EREMOTE;
  case LINUX_ENOLINK:          return ENOLINK;
  case LINUX_EADV:             return EADV;
  case LINUX_ESRMNT:           return ESRMNT;
  case LINUX_ECOMM:            return ECOMM;
  case LINUX_EPROTO:           return EPROTO;
  case LINUX_EMULTIHOP:        return EMULTIHOP;
  case LINUX_EDOTDOT:          return EDOTDOT;
  case LINUX_EBADMSG:          return EBADMSG;
  case LINUX_EOVERFLOW:        return EOVERFLOW;
  case LINUX_ENOTUNIQ:         return ENOTUNIQ;
  case LINUX_EBADFD:           return EBADFD;
  case LINUX_EREMCHG:          return EREMCHG;
  case LINUX_ELIBACC:          return ELIBACC;
  case LINUX_ELIBBAD:          return ELIBBAD;
  case LINUX_ELIBSCN:          return ELIBSCN;
  case LINUX_ELIBMAX:          return ELIBMAX;
  case LINUX_ELIBEXEC:         return ELIBEXEC;
  case LINUX_EILSEQ:           return EILSEQ;
  case LINUX_ERESTART:         return ERESTART;
  case LINUX_ESTRPIPE:         return ESTRPIPE;
  case LINUX_EUSERS:           return EUSERS;
  case LINUX_ENOTSOCK:         return ENOTSOCK;
  case LINUX_EDESTADDRREQ:     return EDESTADDRREQ;
  case LINUX_EMSGSIZE:         return EMSGSIZE;
  case LINUX_EPROTOTYPE:       return EPROTOTYPE;
  case LINUX_ENOPROTOOPT:      return ENOPROTOOPT;
  case LINUX_EPROTONOSUPPORT:  return EPROTONOSUPPORT;
  case LINUX_ESOCKTNOSUPPORT:  return ESOCKTNOSUPPORT;
  case LINUX_EOPNOTSUPP:       return EOPNOTSUPP;
  case LINUX_EPFNOSUPPORT:     return EPFNOSUPPORT;
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
  case LINUX_ESHUTDOWN:        return ESHUTDOWN;
  case LINUX_ETOOMANYREFS:     return ETOOMANYREFS;
  case LINUX_ETIMEDOUT:        return ETIMEDOUT;
  case LINUX_ECONNREFUSED:     return ECONNREFUSED;
  case LINUX_EHOSTDOWN:        return EHOSTDOWN;
  case LINUX_EHOSTUNREACH:     return EHOSTUNREACH;
  case LINUX_EALREADY:         return EALREADY;
  case LINUX_EINPROGRESS:      return EINPROGRESS;
  case LINUX_ESTALE:           return ESTALE;
  case LINUX_EUCLEAN:          return EUCLEAN;
  case LINUX_ENOTNAM:          return ENOTNAM;
  case LINUX_ENAVAIL:          return ENAVAIL;
  case LINUX_EISNAM:           return EISNAM;
  case LINUX_EREMOTEIO:        return EREMOTEIO;
  case LINUX_EDQUOT:           return EDQUOT;
  case LINUX_ENOMEDIUM:        return ENOMEDIUM;
  case LINUX_EMEDIUMTYPE:      return EMEDIUMTYPE;
  case LINUX_ECANCELED:        return ECANCELED;
  case LINUX_ENOKEY:           return ENOKEY;
  case LINUX_EKEYEXPIRED:      return EKEYEXPIRED;
  case LINUX_EKEYREVOKED:      return EKEYREVOKED;
  case LINUX_EKEYREJECTED:     return EKEYREJECTED;
  case LINUX_EOWNERDEAD:       return EOWNERDEAD;
  case LINUX_ENOTRECOVERABLE:  return ENOTRECOVERABLE;
  case LINUX_ERFKILL:          return ERFKILL;
  case LINUX_EHWPOISON:        return EHWPOISON;
  default:
    assert(false);
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
  case ENOTBLK:          return LINUX_ENOTBLK;
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
  case ECHRNG:           return LINUX_ECHRNG;
  case EL2NSYNC:         return LINUX_EL2NSYNC;
  case EL3HLT:           return LINUX_EL3HLT;
  case EL3RST:           return LINUX_EL3RST;
  case ELNRNG:           return LINUX_ELNRNG;
  case EUNATCH:          return LINUX_EUNATCH;
  case ENOCSI:           return LINUX_ENOCSI;
  case EL2HLT:           return LINUX_EL2HLT;
  case EBADE:            return LINUX_EBADE;
  case EBADR:            return LINUX_EBADR;
  case EXFULL:           return LINUX_EXFULL;
  case ENOANO:           return LINUX_ENOANO;
  case EBADRQC:          return LINUX_EBADRQC;
  case EBADSLT:          return LINUX_EBADSLT;
  case EBFONT:           return LINUX_EBFONT;
  case ENOSTR:           return LINUX_ENOSTR;
  case ENODATA:          return LINUX_ENODATA;
  case ETIME:            return LINUX_ETIME;
  case ENOSR:            return LINUX_ENOSR;
  case ENONET:           return LINUX_ENONET;
  case ENOPKG:           return LINUX_ENOPKG;
  case EREMOTE:          return LINUX_EREMOTE;
  case ENOLINK:          return LINUX_ENOLINK;
  case EADV:             return LINUX_EADV;
  case ESRMNT:           return LINUX_ESRMNT;
  case ECOMM:            return LINUX_ECOMM;
  case EPROTO:           return LINUX_EPROTO;
  case EMULTIHOP:        return LINUX_EMULTIHOP;
  case EDOTDOT:          return LINUX_EDOTDOT;
  case EBADMSG:          return LINUX_EBADMSG;
  case EOVERFLOW:        return LINUX_EOVERFLOW;
  case ENOTUNIQ:         return LINUX_ENOTUNIQ;
  case EBADFD:           return LINUX_EBADFD;
  case EREMCHG:          return LINUX_EREMCHG;
  case ELIBACC:          return LINUX_ELIBACC;
  case ELIBBAD:          return LINUX_ELIBBAD;
  case ELIBSCN:          return LINUX_ELIBSCN;
  case ELIBMAX:          return LINUX_ELIBMAX;
  case ELIBEXEC:         return LINUX_ELIBEXEC;
  case EILSEQ:           return LINUX_EILSEQ;
  case ERESTART:         return LINUX_ERESTART;
  case ESTRPIPE:         return LINUX_ESTRPIPE;
  case EUSERS:           return LINUX_EUSERS;
  case ENOTSOCK:         return LINUX_ENOTSOCK;
  case EDESTADDRREQ:     return LINUX_EDESTADDRREQ;
  case EMSGSIZE:         return LINUX_EMSGSIZE;
  case EPROTOTYPE:       return LINUX_EPROTOTYPE;
  case ENOPROTOOPT:      return LINUX_ENOPROTOOPT;
  case EPROTONOSUPPORT:  return LINUX_EPROTONOSUPPORT;
  case ESOCKTNOSUPPORT:  return LINUX_ESOCKTNOSUPPORT;
  case EOPNOTSUPP:       return LINUX_EOPNOTSUPP;
  case EPFNOSUPPORT:     return LINUX_EPFNOSUPPORT;
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
  case ESHUTDOWN:        return LINUX_ESHUTDOWN;
  case ETOOMANYREFS:     return LINUX_ETOOMANYREFS;
  case ETIMEDOUT:        return LINUX_ETIMEDOUT;
  case ECONNREFUSED:     return LINUX_ECONNREFUSED;
  case EHOSTDOWN:        return LINUX_EHOSTDOWN;
  case EHOSTUNREACH:     return LINUX_EHOSTUNREACH;
  case EALREADY:         return LINUX_EALREADY;
  case EINPROGRESS:      return LINUX_EINPROGRESS;
  case ESTALE:           return LINUX_ESTALE;
  case EUCLEAN:          return LINUX_EUCLEAN;
  case ENOTNAM:          return LINUX_ENOTNAM;
  case ENAVAIL:          return LINUX_ENAVAIL;
  case EISNAM:           return LINUX_EISNAM;
  case EREMOTEIO:        return LINUX_EREMOTEIO;
  case EDQUOT:           return LINUX_EDQUOT;
  case ENOMEDIUM:        return LINUX_ENOMEDIUM;
  case EMEDIUMTYPE:      return LINUX_EMEDIUMTYPE;
  case ECANCELED:        return LINUX_ECANCELED;
  case ENOKEY:           return LINUX_ENOKEY;
  case EKEYEXPIRED:      return LINUX_EKEYEXPIRED;
  case EKEYREVOKED:      return LINUX_EKEYREVOKED;
  case EKEYREJECTED:     return LINUX_EKEYREJECTED;
  case EOWNERDEAD:       return LINUX_EOWNERDEAD;
  case ENOTRECOVERABLE:  return LINUX_ENOTRECOVERABLE;
  case ERFKILL:          return LINUX_ERFKILL;
  case EHWPOISON:        return LINUX_EHWPOISON;
  // Darwin-specific errors
  case EFTYPE:           return LINUX_EPERM;
  case EAUTH:            return LINUX_EPERM;
  case ENEEDAUTH:        return LINUX_EPERM;
  case EBADEXEC:         return LINUX_ENOEXEC;
  case EBADARCH:         return LINUX_ENOEXEC;
  case EBADMACHO:        return LINUX_ENOEXEC;
  case ENOATTR:          return LINUX_ENODATA;
  case ENOPOLICY:        return LINUX_EPERM;
  case EBADRPC:          return LINUX_EPERM;
  default:
    assert(false);
  }
}

int
native_to_linux_mprot(int darwin_prot)
{
  int linux_prot = 0;
  if (darwin_prot & PROT_READ)
    linux_prot |= LINUX_PROT_READ;
  if (darwin_prot & PROT_WRITE)
    linux_prot |= LINUX_PROT_WRITE;
  if (darwin_prot & PROT_EXEC)
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
linux_to_native_o_flags(int l_flags)
{
  int ret = 0;
  if (l_flags & LINUX_O_PATH) {
    if (l_flags & LINUX_O_CLOEXEC)
      ret |= O_CLOEXEC;
    if (l_flags & LINUX_O_NOFOLLOW)
      ret |= O_SYMLINK;
    if (l_flags & LINUX_O_DIRECTORY)
      ret |= O_DIRECTORY;
    return ret;
  }
  switch (l_flags & LINUX_O_ACCMODE) {
  case LINUX_O_WRONLY:
    ret |= O_WRONLY;
    break;
  case LINUX_O_RDWR:
    ret |= O_RDWR;
    break;
  default:                      /* Note: LINUX_O_RDONLY == 0 */
    ret |= O_RDONLY;
  }
  if (l_flags & LINUX_O_NDELAY)
    ret |= O_NONBLOCK;
  if (l_flags & LINUX_O_APPEND)
    ret |= O_APPEND;
  if (l_flags & LINUX_O_SYNC)
    ret |= O_FSYNC;
  if (l_flags & LINUX_O_NONBLOCK)
    ret |= O_NONBLOCK;
  if (l_flags & LINUX_FASYNC)
    ret |= O_ASYNC;
  if (l_flags & LINUX_O_CREAT)
    ret |= O_CREAT;
  if (l_flags & LINUX_O_TRUNC)
    ret |= O_TRUNC;
  if (l_flags & LINUX_O_EXCL)
    ret |= O_EXCL;
  if (l_flags & LINUX_O_NOCTTY)
    ret |= O_NOCTTY;
  /* if (l_flags & LINUX_O_DIRECT) */
  /*   ret |= O_DIRECT; */
  if (l_flags & LINUX_O_NOFOLLOW)
    ret |= O_NOFOLLOW;
  if (l_flags & LINUX_O_DIRECTORY)
    ret |= O_DIRECTORY;

  return ret;
}
