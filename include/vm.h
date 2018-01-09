#ifndef NOAH_VMM_H
#define NOAH_VMM_H

#include <vmm.h>

#include "types.h"
#include "noah.h"

void create_vm(void);
void destroy_vm(void);

void create_vcpu(void);
void destroy_vcpu(void);

int run_vcpu(void);

void read_register(vmm_x64_reg_t, uint64_t *);
void write_register(vmm_x64_reg_t, uint64_t);
void read_msr(uint32_t, uint64_t *);
void write_msr(uint32_t, uint64_t);
void get_vcpu_state(int id, uint64_t *);

void write_fpstate(void *, size_t);

void vm_mmap(gaddr_t addr, size_t len, int prot, void *ptr);
void vm_munmap(gaddr_t addr, size_t len);

#endif
