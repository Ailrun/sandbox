#ifndef ARCH_AARCH64
#define ARCH_AARCH64

#include "arch_base.h"

extern "C" {
#include <stdint.h>
#include <string.h>

#include <sys/user.h>
}

class SyscallInfo : public SyscallInfoBase<struct user_regs_struct, unsigned long long> {
public:
  bool is_compat_regset;
  bool is_compat_table;
  inline SyscallInfo(ThreadData &thread)
      : SyscallInfoBase(thread, false), is_compat_regset(false),
        is_compat_table(false) {
    struct iovec iov = {.iov_base = (void *)&regs, .iov_len = sizeof regs};
    thread.ptrace_getregset(NT_PRSTATUS, iov);
  }

  virtual inline unsigned long long &sysnum() { return regs.regs[8]; }
  virtual inline unsigned long long &ret() { return regs.regs[0]; }
  virtual inline unsigned long long &arg(int arg) {
    switch (arg) {
    case 1:
      return regs.regs[0];
    case 2:
      return regs.regs[1];
    case 3:
      return regs.regs[2];
    case 4:
      return regs.regs[3];
    case 5:
      return regs.regs[4];
    case 6:
      return regs.regs[5];
    }

    return regs.sp;
  }
  virtual inline unsigned long long &stack() { return regs.sp; }

  bool save() {
    struct iovec iov = {.iov_base = (void *)&regs, .iov_len = sizeof regs};
    return thread.ptrace_setregset(NT_PRSTATUS, iov);
  }
};

#endif
