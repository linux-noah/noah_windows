#ifndef NOAH_PROC_H
#define NOAH_PROC_H

int platform_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls);
int platform_restore_proc(uint64_t pid);

#endif
