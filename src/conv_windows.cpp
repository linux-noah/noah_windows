extern "C" {
#include <stdlib.h>

#include "cross_platform.h"
#include "common.h"
#include "noah.h"

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
