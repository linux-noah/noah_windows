#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vmm.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#ifdef __APPLE__
#include <libgen.h>
#include <sys/syslimits.h>
#endif
#endif

#include "vm.h"
#include "mm.h"
#include "util/list.h"

#include "x86/vm.h"
#include "x86/vmx.h"

struct vcpu {
  struct list_head list;
  vmm_cpu_t vcpuid;
};

vmm_vm_t vm;
struct list_head vcpus;
int nr_vcpus;
pthread_rwlock_t alloc_lock;

_Thread_local static struct vcpu *vcpu;

void
vm_mmap(gaddr_t gaddr, size_t size, int prot, void *haddr)
{
  assert(is_page_aligned(haddr, PAGE_4KB));
  assert(is_page_aligned((void *) gaddr, PAGE_4KB));
  assert(is_page_aligned((void *) size, PAGE_4KB));

  vmm_memory_unmap(vm, gaddr, size);
  if (vmm_memory_map(vm, haddr, gaddr, size, prot) != VMM_SUCCESS) {
    panic("vmm_memory_map failed\n");
  }
}

void
vm_munmap(gaddr_t gaddr, size_t size)
{
  assert(is_page_aligned((void *) size, PAGE_4KB));
  vmm_memory_unmap(vm, gaddr, size);
}

void
write_fpstate(void *buffer, size_t size)
{
  // TODO
}

void
create_vm()
{
  vmm_return_t ret;

  /* initialize global variables */
  pthread_rwlock_init(&alloc_lock, NULL);
  INIT_LIST_HEAD(&vcpus);
  nr_vcpus = 0;

  /* create the VM */
  ret = vmm_create(&vm);
  if (ret != VMM_SUCCESS) {
    panic("could not create the vm: error code %x", ret);
    return;
  }

  printk("successfully created the vm\n");

  create_vcpu();

  printk("successfully created a vcpu\n");
}

void
destroy_vm()
{
  vmm_return_t ret;

  struct list_head *p;
  list_for_each(p, &vcpus) {
    struct vcpu *vcpu = (struct vcpu *)p;
    ret = vmm_cpu_destroy(vm, vcpu->vcpuid);
    if (ret != VMM_SUCCESS) {
      panic("could not destroy the vcpu: error code %x", ret);
      exit(1);
    }
  }

  printk("successfully destroyed the vcpu\n");

  ret = vmm_destroy(vm);
  if (ret != VMM_SUCCESS) {
    panic("could not destroy the vm: error code %x", ret);
    exit(1);
  }

  printk("successfully destroyed the vm\n");
}

void
create_vcpu()
{
  vmm_return_t ret;
  vmm_cpu_t vcpuid;

  ret = vmm_cpu_create(vm, &vcpuid);
  if (ret != VMM_SUCCESS) {
    panic("could not create a vcpu: error code %x", ret);
    return;
  }

  assert(vcpu == NULL);

  vcpu = reinterpret_cast<struct vcpu *>(calloc(sizeof(struct vcpu), 1));
  vcpu->vcpuid = vcpuid;

  pthread_rwlock_wrlock(&alloc_lock);
  list_add(&vcpu->list, &vcpus);
  nr_vcpus++;
  pthread_rwlock_unlock(&alloc_lock);
}

void
destroy_vcpu(void)
{
  pthread_rwlock_wrlock(&alloc_lock);
  list_del(&vcpu->list);
  nr_vcpus--;
  vmm_cpu_destroy(vm, vcpu->vcpuid);
  free(vcpu);
  vcpu = NULL;
  pthread_rwlock_unlock(&alloc_lock);
}

void
print_regs()
{
  uint64_t value;

  read_register(VMM_X64_RIP, &value);
  printk("\trip = 0x%llx\n", value);
  read_register(VMM_X64_RAX, &value);
  printk("\trax = 0x%llx\n", value);
  read_register(VMM_X64_RBX, &value);
  printk("\trbx = 0x%llx\n", value);
  read_register(VMM_X64_RCX, &value);
  printk("\trcx = 0x%llx\n", value);
  read_register(VMM_X64_RDX, &value);
  printk("\trdx = 0x%llx\n", value);
  read_register(VMM_X64_RDI, &value);
  printk("\trdi = 0x%llx\n", value);
  read_register(VMM_X64_RSI, &value);
  printk("\trsi = 0x%llx\n", value);
  read_register(VMM_X64_RBP, &value);
  printk("\trbp = 0x%llx\n", value);
}

void
dump_instr()
{
  // TODO
  printk("dump_instr() is not implementd yet on cross platform.\n");
}

void
read_register(vmm_x64_reg_t reg, uint64_t *val) {
  if (vmm_cpu_get_register(vm, vcpu->vcpuid, reg, val) != VMM_SUCCESS) {
    fprintf(stderr, "write_register failed\n");
    abort();
  }
}

void
write_register(vmm_x64_reg_t reg, uint64_t val) {
  if (vmm_cpu_set_register(vm, vcpu->vcpuid, reg, val) != VMM_SUCCESS) {
    fprintf(stderr, "write_register failed\n");
    abort();
  }
}

void
read_msr(uint32_t reg, uint64_t *val)
{
  if (vmm_cpu_get_msr(vm, vcpu->vcpuid, reg, val) != VMM_SUCCESS) {
    fprintf(stderr, "read_msr failed\n");
    abort();
  }
}

void
write_msr(uint32_t reg, uint64_t val) {
  if (vmm_cpu_set_msr(vm, vcpu->vcpuid, reg, val) != VMM_SUCCESS) {
    fprintf(stderr, "write_msr failed\n");
    abort();
  }
}

int
run_vcpu()
{
  if (vmm_cpu_run(vm, vcpu->vcpuid) == VMM_SUCCESS) {
    return 0;
  }
  return -1;
}

void
get_vcpu_state(int id, uint64_t *val)
{
  if (vmm_cpu_get_state(vm, vcpu->vcpuid, id, val) != VMM_SUCCESS) {
    fprintf(stderr, "get_vcpu_state failed\n");
    abort();
  }
}
