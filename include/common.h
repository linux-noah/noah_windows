#include <stdint.h>
#include "cross_platform.h"


/*
 * ``_MAP(f, t0, v0, t1, v1, ...)'' => ``f(t0, v0), f(t1, v1), ...''
 */

#define _EXPAND_VA_ARGS(x) x  // Workaround for VC++'s macro expansion bug. Force it to recognize
                            // the expansion result of __VA_ARGS__ as multiple inputs
#define _MAP(f,...) _EXPAND_VA_ARGS(_DISPATCH(__VA_ARGS__,_MAP7,,_MAP6,,_MAP5,,_MAP4,,_MAP3,,_MAP2,,_MAP1,_MAP0)(f,__VA_ARGS__))
#define _MAP0(f,...)
#define _MAP1(f,t,v)     f(t,v)
#define _MAP2(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP1(f,__VA_ARGS__))
#define _MAP3(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP2(f,__VA_ARGS__))
#define _MAP4(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP3(f,__VA_ARGS__))
#define _MAP5(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP4(f,__VA_ARGS__))
#define _MAP6(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP5(f,__VA_ARGS__))
#define _MAP7(f,t,v,...) f(t,v), _EXPAND_VA_ARGS(_MAP6(f,__VA_ARGS__))
#define _DISPATCH(T0,V0,T1,V1,T2,V2,T3,V3,T4,V4,T5,V5,T6,V6,X,...) X


// system call declartion macros
#define MK_DECL(t,v) t v
#define MK_TEMP(t,v) uint64_t temp__##v
#define MK_CAST(t,v) (t) temp__##v

// strace related macros
#define MK_STRACE_CALL(t,v) #t, #v, temp__##v
#define temp__0             0  // argument terminator

// macros to put padding so that the number of arguments of _sys_foo becomes six
#define _PAD_TO_6(...) _EXPAND_VA_ARGS(_DISPATCH(__VA_ARGS__,_PAD_N,,_PAD_N,,_PAD_N,,_PAD_N,,_PAD_N,,_PAD_N,,_PAD_N,_PAD_0)(__VA_ARGS__))
// The case is divided into where the values is 0 and larger to trim trailing comma after __VA_ARGS__
#define _PAD_0()       uint64_t, pad0, uint64_t, pad1, uint64_t, pad2, uint64_t, pad3, uint64_t, pad4, uint64_t, pad5
#define _PAD_N(...)    _EXPAND_VA_ARGS(_TAKE_6(__VA_ARGS__, uint64_t, pad0, uint64_t, pad1, uint64_t, pad2, uint64_t, pad3, uint64_t, pad4, uint64_t, pad5))
#define _TAKE_6(T0,V0,T1,V1,T2,V2,T3,V3,T4,V4,T5,V5,...) T0,V0,T1,V1,T2,V2,T3,V3,T4,V4,T5,V5


#define DECLARE_SCFUNCT(name, ...)                      \
  uint64_t sys_##name(_EXPAND_VA_ARGS(_MAP(MK_DECL, __VA_ARGS__)));

#define DEFINE_SCWRAPPER(name, ...)                                                \
  uint64_t _sys_##name(_EXPAND_VA_ARGS(_MAP(MK_TEMP,_PAD_TO_6(__VA_ARGS__)))) {                                 \
    /* TODO: Replace "##" with some non-GNU trick */ \
    /* meta_strace_pre(LSYS_##name, #name, _EXPAND_VA_ARGS(_MAP(MK_STRACE_CALL, ##__VA_ARGS__, 0, 0))); */    \
    uint64_t ret = sys_##name(_EXPAND_VA_ARGS(_MAP(MK_CAST,__VA_ARGS__)));                         \
    /* meta_strace_post(LSYS_##name, #name, ret, _EXPAND_VA_ARGS(_MAP(MK_STRACE_CALL, ##__VA_ARGS__, 0, 0))); */\
    return ret;                                                                    \
  }

#define DEFINE_SCFUNCT(name, ...)                       \
  uint64_t sys_##name(_EXPAND_VA_ARGS(_MAP(MK_DECL, __VA_ARGS__)))

#define DEFINE_SYSCALL(name, ...)               \
  _EXPAND_VA_ARGS(DECLARE_SCFUNCT(name, ##__VA_ARGS__))          \
  _EXPAND_VA_ARGS(DEFINE_SCWRAPPER(name, ##__VA_ARGS__))         \
  _EXPAND_VA_ARGS(DEFINE_SCFUNCT(name, ##__VA_ARGS__))           


/*
 * syscall errno wrapper
 */
#include "linux/errno.h"

#define syswrap(syscall) (errno = 0, _syswrap(syscall))
static inline int _syswrap(int sys_ret) {
  return (sys_ret < 0 && errno != 0) ? -native_to_linux_errno(errno) : sys_ret;
}

#include "syscall.h"

enum sc_numbers {
// omit duplicted "unimplemented"s by expanding them to LSYS_(an unique number)
#define unimplemented __COUNTER__
#define OMIT_UNIMPLEMENTED(LSYS_, name) LSYS_ ## name
#define SYSCALL(n, name) OMIT_UNIMPLEMENTED(LSYS_, name) = n,
  SYSCALLS
#undef SYSCALL
#undef unimplemented
  LSYS_unimplemented = -1
};
