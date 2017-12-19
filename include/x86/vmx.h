#ifndef NOAH_X86_VMX_H
#define NOAH_X86_VMX_H

#include <stdint.h>
#include <vmm.h>

#define NR_X86_REG_LIST (sizeof(x86_reg_list) / sizeof(uint32_t) - 1)

#define X86_REG_ENTRIES                             \
  X86_REG(VMM_X64_RIP)                               \
  X86_REG(VMM_X64_RFLAGS)                            \
  X86_REG(VMM_X64_RAX)                               \
  X86_REG(VMM_X64_RCX)                               \
  X86_REG(VMM_X64_RDX)                               \
  X86_REG(VMM_X64_RBX)                               \
  X86_REG(VMM_X64_RSI)                               \
  X86_REG(VMM_X64_RDI)                               \
  X86_REG(VMM_X64_RSP)                               \
  X86_REG(VMM_X64_RBP)                               \
  X86_REG(VMM_X64_R8)                                \
  X86_REG(VMM_X64_R9)                                \
  X86_REG(VMM_X64_R10)                               \
  X86_REG(VMM_X64_R11)                               \
  X86_REG(VMM_X64_R12)                               \
  X86_REG(VMM_X64_R13)                               \
  X86_REG(VMM_X64_R14)                               \
  X86_REG(VMM_X64_R15)                               \
  X86_REG(VMM_X64_CS)                                \
  X86_REG(VMM_X64_SS)                                \
  X86_REG(VMM_X64_DS)                                \
  X86_REG(VMM_X64_ES)                                \
  X86_REG(VMM_X64_FS)                                \
  X86_REG(VMM_X64_GS)                                \
  X86_REG(VMM_X64_IDT_BASE)                          \
  X86_REG(VMM_X64_IDT_LIMIT)                         \
  X86_REG(VMM_X64_GDT_BASE)                          \
  X86_REG(VMM_X64_GDT_LIMIT)                         \
  X86_REG(VMM_X64_LDTR)                              \
  X86_REG(VMM_X64_LDT_BASE)                          \
  X86_REG(VMM_X64_LDT_LIMIT)                         \
  X86_REG(VMM_X64_LDT_AR)                            \
  X86_REG(VMM_X64_TR)                                \
  X86_REG(VMM_X64_TSS_BASE)                          \
  X86_REG(VMM_X64_TSS_LIMIT)                         \
  X86_REG(VMM_X64_TSS_AR)                            \
  X86_REG(VMM_X64_CR0)                               \
  X86_REG(VMM_X64_CR1)                               \
  X86_REG(VMM_X64_CR2)                               \
  X86_REG(VMM_X64_CR3)                               \
  X86_REG(VMM_X64_CR4)                               \
  X86_REG(VMM_X64_DR0)                               \
  X86_REG(VMM_X64_DR1)                               \
  X86_REG(VMM_X64_DR2)                               \
  X86_REG(VMM_X64_DR3)                               \
  X86_REG(VMM_X64_DR4)                               \
  X86_REG(VMM_X64_DR5)                               \
  X86_REG(VMM_X64_DR6)                               \
  X86_REG(VMM_X64_DR7)                               \
  X86_REG(VMM_X64_TPR)                               \
  X86_REG(VMM_X64_XCR0)                              \
  X86_REG(VMM_X64_REGISTERS_MAX)

static const uint32_t x86_reg_list[] = {
#define X86_REG(x) x,
  X86_REG_ENTRIES
#undef X86_REG
};

static const char *x86_reg_str[] = {
#define X86_REG(x) #x,
  X86_REG_ENTRIES
#undef X86_REG
};

#define VMCS_EXCTYPE_EXTERNAL_INTERRUPT 0
#define VMCS_EXCTYPE_NONMASKTABLE_INTERRUPT 2
#define VMCS_EXCTYPE_HARDWARE_EXCEPTION 3
#define VMCS_EXCTYPE_SOFTWARE_EXCEPTION 6


#endif
