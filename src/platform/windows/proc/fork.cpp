#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <string>
#include <Windows.h>

extern "C" {
#include "common.h"
#include "noah.h"
#include "syscall.h"
}

int
platform_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  // # What to Do Beforehand for CoW
  // 1. Being Able to Hook Exceptions
  // 2. Prepare read-only page mapping structure
  //     1. Straight mapping
  // # What to Do in This Process Here
  // 1. Replace CR3's page mapping with read only one
  // 2. Create new proc structure
  //     1. allocate new proc from shared memroy
  //     2. copy proc structure
  //     3. copy mm and so on
  //     4. copy vkern_mm
  // 3. Take a snapshot of the VM
  //     1. Copy registers and VMCS of the VM
  //     2. Save it to vkern_shm
  // 4. Create process
  //     1. Construct command line or environment var that tell handle of vkern_shm
  //     2. Call CreateProcess
  //     3. Done. The new process restores its process-state
  // 5. Setup the new state
  //     1. set new PID in rax
  // # What to Do in the New Process
  // 1. The new process restores its state
  //     1. Setup vkern_shm by the argument
  //     2. Restore the VM state
  //         1. Create a VM
  //         2. Restore its state from vkern_shm
  //     3. Skip init_blahblah, but restores vkernel's state by inherited handles
  //         1. map vkern_mm from copied vkern_mm
  //         2. map proc->mm 
  // 2. Setup the new state
  //     1. set 0 in rax
  // # What to Do in Page Fault for CoW
  // 1. Check if the page is read-only and the access is write
  // 2. If so, unmap the page's region
  // 3. Map new region
  //     NOTE: Create a page with the size of just a one page? or the whole mapping region?
  //           See Linux's implementation
  // 4. Now, the mapping becomes like
  //    _______________-------------_____________
  //    Read-only CoW  New writable Read-only CoW
  //        pages        page(s?)        pages
  // 5. Copy the contents of the page
  // 6. Make the region writable in guest's CR3

  return -LINUX_EINVAL;
}
