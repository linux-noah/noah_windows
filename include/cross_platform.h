#ifndef NOAH_CROSS_PLATFORM_H
#define NOAH_CROSS_PLATFORM_H

#ifdef _WIN32

#include <windows.h>

#define ATTR_CHECK_FORMAT()
#define noreturn [[noreturn]]

#define PACK(declare) __pragma( pack(push, 1) ) declare __pragma( pack(pop) )

// Temporalily map constants from POSIX's to Windows's
#define PROT_READ  GENERIC_READ 
#define PROT_WRITE GENERIC_WRITE
#define PROT_EXEC  GENERIC_EXECUTE

#define ssize_t int

#define _Thread_local

#else

#define ATTR_CHECK_FORMAT(format_func, ...) __attribute__((format(format_func, __VA_ARGS__)))


#include <stdnoreturn.h>
#include <pthread.h>

#define PACK(declare) declare __attribute__((__packed__))

#endif


#endif
