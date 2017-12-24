#ifndef NOAH_TYPES_H
#define NOAH_TYPES_H

#if defined(__unix__) || defined(TARGET_OS_MAC)
#include <unistd.h>
#elif defined(_WIN32)
#include <sys/types.h>
#endif

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef uint64_t gaddr_t;
typedef gaddr_t  gstr_t;

#endif
