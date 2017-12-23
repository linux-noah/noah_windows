#include <stdint.h>
#include <stdbool.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

// macOS's standard library has built-in roundup/rounddown macro
#ifndef rounddown
static inline uint64_t rounddown(uint64_t x, uint64_t y) {
  return x / y * y;
}
#endif

#ifndef roundup
static inline uint64_t roundup(uint64_t x, uint64_t y) {
  return (x + y - 1) / y * y;
}
#endif

#define is_aligned(x,y) (((x) / (y) * (y))== (x))
