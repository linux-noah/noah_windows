#ifndef NOAH_CROSS_PLATFORM_H
#define NOAH_CROSS_PLATFORM_H

#ifdef _WIN32

#include <windows.h>

#define ATTR_CHECK_FORMAT()
#define noreturn [[noreturn]]
#define TYPEDEF_PAGE_ALIGNED(t) typedef t __declspec(align(0x1000)) 

#define PACK(declare) __pragma( pack(push, 1) ) declare __pragma( pack(pop) )

// Temporalily map constants from POSIX's to Windows's
#define PROT_READ  GENERIC_READ 
#define PROT_WRITE GENERIC_WRITE
#define PROT_EXEC  GENERIC_EXECUTE

#define ssize_t int

#define _Thread_local

noreturn static void _f_noreturn() {};
#define UNREACHABLE() _f_noreturn()


// Temporary stubs for pthread

#define pthread_rwlock_t void *
#define pthread_cond_t void*
#define pthread_mutex_t void *
#define PTHREAD_RWLOCK_INITIALIZER NULL
#define PTHREAD_MUTEX_INITIALIZER NULL

#define pthread_rwlock_wrlock(...)
#define pthread_rwlock_unlock(...)
#define pthread_mutex_lock(...)
#define pthread_mutex_unlock(...)
#define pthread_threadid_np(...) -1
#define pthread_rwlock_init(...)
#define pthread_exit(...)



#else


#define ATTR_CHECK_FORMAT(format_func, ...) __attribute__((format(format_func, __VA_ARGS__)))


#include <stdnoreturn.h>
#include <pthread.h>

#define PACK(declare) declare __attribute__((__packed__))

#define TYPEDEF_PAGE_ALIGNED(t) typedef t __attribute__ ((aligned(0x1000))) 

#define UNREACHABLE() __builtin_unreachable()

#endif


#endif
