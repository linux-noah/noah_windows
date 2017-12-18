#ifndef NOAH_VMM_H
#define NOAH_VMM_H

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <Hypervisor/hv_arch_vmx.h>

#include "types.h"
#include "noah.h"
#include "x86/vmx.h"

struct vcpu_snapshot {
  uint64_t vcpu_reg[NR_X86_REG_LIST];
  uint64_t vmcs[NR_VMCS_FIELD];
  char fpu_states[512] __attribute__((aligned(16)));
};

struct vm_snapshot {
  struct vcpu_snapshot first_vcpu_snapshot;
};

void create_vm(void);
void destroy_vm(void);
void snapshot_vm(struct vm_snapshot*);
void restore_vm(struct vm_snapshot*);
void snapshot_vcpu(struct vcpu_snapshot*);
void restore_vcpu(struct vcpu_snapshot*);

void create_vcpu(struct vcpu_snapshot *);
void destroy_vcpu(void);

int run_vcpu(void);

void read_register(hv_x86_reg_t, uint64_t *);
void write_register(hv_x86_reg_t, uint64_t);
void read_msr(uint32_t, uint64_t *);
void write_msr(uint32_t, uint64_t);
void read_vmcs(uint32_t, uint64_t *);
void write_vmcs(uint32_t, uint64_t);

void write_fpstate(void *, size_t);

void enable_native_msr(uint32_t, bool);

/* prot is obtained by or'ing HV_MEMORY_READ, HV_MEMORY_EXEC, HV_MEMORY_WRITE */
void vm_mmap(gaddr_t addr, size_t len, int prot, void *ptr);
void vm_munmap(gaddr_t addr, size_t len);

#endif
