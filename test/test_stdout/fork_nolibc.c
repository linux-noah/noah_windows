#include "noah.h"

// Note: This test passes even if CoW is not working
int main()
{
  if (fork() != 0) {
    _exit(0);
  }
  const char str[] = "hello, world!\n";
  write(1, str, sizeof str - 1);
  return 0;
}
