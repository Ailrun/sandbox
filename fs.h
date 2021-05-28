#ifndef FS_H
#define FS_H

#include <string>
#include <vector>

#include "arch.h"
#include "config.h"
#include "path.h"
#include "sandbox.h"
#include "wakeup.h"

extern "C" {
#include <fcntl.h>
#include <stdio.h>
#include <syscall.h>

#include <sys/wait.h>
}

template <typename T> class FsThread : public Thread<T> {
public:
  FsThread<T>(pid_t tid) : Thread<T>(tid), ret_override(false) {}

  bool ret_override;
  long ret_val;

  long restore_addr;
  std::vector<uint8_t> restore_data;

  void block(SyscallInfo &i, long val) {
    i.sysnum() = -1;
    i.save();
    ret_override = true;
    ret_val = val;
  }

  virtual bool can_see_path(std::string path, int at, int &error) {
    return true;
  }
  virtual bool can_write_path(std::string path, int at, int &error) {
    return true;
  }
  virtual bool can_create_thread(Sandbox<T> &s) { return true; }
  virtual bool should_replace_path(std::string path, std::string &newpath,
                                   int at = AT_FDCWD, int flags = 0) {
    return false;
  }
  virtual bool should_replace_stat(std::string path, struct stat &st,
                                   int at = AT_FDCWD, int flags = 0) {
    return false;
  }
  virtual void after_replace_path(bool success) {}

  virtual void on_syscall_entry(Sandbox<T> &s) {
    SyscallInfo i(*this);
    if (i.is_compat_table)
      return block(i, -ENOSYS);
    switch (i.sysnum()) {
    case WAKE_MAGIC:
      if (conf_wakeup)
        do_wakeup();
      return;
    case SYS_read:
    case SYS_write:
    case SYS_close:
#ifdef __x86_64__
    case SYS_poll:
#endif
    case SYS_lseek:
    case SYS_mmap:
    case SYS_mprotect:
    case SYS_munmap:
    case SYS_brk:
    case SYS_rt_sigaction:
    case SYS_rt_sigprocmask:
    case SYS_rt_sigreturn:
    case SYS_ioctl:
    case SYS_pread64:
    case SYS_pwrite64:
    case SYS_readv:
    case SYS_writev:
#ifdef __x86_64__
    case SYS_pipe:
    case SYS_select:
#endif
    case SYS_sched_yield:
    case SYS_mremap:
    case SYS_msync:
    case SYS_mincore:
    case SYS_madvise:
    case SYS_dup:
#ifdef __x86_64__
    case SYS_dup2:
    case SYS_pause:
#endif
    case SYS_nanosleep:
    case SYS_getitimer:
#ifdef __x86_64__
    case SYS_alarm:
#endif
    case SYS_setitimer:
    case SYS_getpid:
    case SYS_sendfile:
    case SYS_exit:
    case SYS_wait4:
    case SYS_uname:
    case SYS_fcntl:
    case SYS_flock:
    case SYS_fsync:
    case SYS_fdatasync:
    case SYS_ftruncate:
#ifdef __x86_64__
    case SYS_getdents:
#endif
    case SYS_getdents64:
    case SYS_getcwd:
    case SYS_fchdir:
    case SYS_fchmod:
    case SYS_fchown:
    case SYS_umask:
    case SYS_gettimeofday:
    case SYS_getrlimit:
    case SYS_getrusage:
    case SYS_sysinfo:
    case SYS_times:
    case SYS_getuid:
    case SYS_getgid:
    case SYS_geteuid:
    case SYS_getegid:
    case SYS_setpgid:
    case SYS_getppid:
#ifdef __x86_64__
    case SYS_getpgrp:
#endif
    case SYS_getgroups:
    case SYS_getresuid:
    case SYS_getresgid:
    case SYS_getpgid:
    case SYS_getsid:
    case SYS_rt_sigpending:
    case SYS_rt_sigtimedwait:
    case SYS_rt_sigqueueinfo:
    case SYS_rt_sigsuspend:
    case SYS_sigaltstack:
#ifdef __x86_64__
    case SYS_utime:
#endif
    case SYS_personality:
    case SYS_fstatfs:
    case SYS_getpriority:
    case SYS_sched_getparam:
    case SYS_sched_getscheduler:
    case SYS_sched_get_priority_max:
    case SYS_sched_get_priority_min:
    case SYS_sched_rr_get_interval:
#ifdef __x86_64__
    case SYS_arch_prctl:
#endif
    case SYS_setrlimit:
    case SYS_gettid:
    case SYS_readahead:
#ifdef __x86_64__
    case SYS_time:
#endif
    case SYS_futex:
    case SYS_fgetxattr:
    case SYS_sched_getaffinity:
#ifdef __x86_64__
    case SYS_epoll_create:
    case SYS_epoll_ctl_old:
    case SYS_epoll_wait_old:
#endif
    case SYS_ppoll:
    case SYS_restart_syscall:
    case SYS_set_tid_address:
    case SYS_fadvise64:
    case SYS_timer_create:
    case SYS_timer_settime:
    case SYS_timer_gettime:
    case SYS_timer_getoverrun:
    case SYS_timer_delete:
    case SYS_clock_gettime:
    case SYS_clock_getres:
    case SYS_exit_group:
#ifdef __x86_64__
    case SYS_epoll_wait:
#endif
    case SYS_epoll_ctl:
    case SYS_set_robust_list:
    case SYS_get_robust_list:
    case SYS_epoll_pwait:
#ifdef __x86_64__
    case SYS_eventfd:
#endif
    case SYS_eventfd2:
    case SYS_epoll_create1:
    case SYS_splice:
    case SYS_tee:
    case SYS_timerfd_create:
    case SYS_timerfd_settime:
    case SYS_timerfd_gettime:
    case SYS_dup3:
    case SYS_pipe2:
    case SYS_preadv:
    case SYS_pwritev:
    case SYS_get_mempolicy:
    case SYS_preadv2:
    case SYS_pwritev2:
      return;
#ifdef __x86_64__
    case SYS_open: {
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(1), path))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, AT_FDCWD, error))
        return block(i, error);
      error = -EPERM;
      if ((i.arg(2) & O_ACCMODE) != O_RDONLY &&
          !can_write_path(path, AT_FDCWD, error))
        return block(i, error);

      std::string newpath;
      if (should_replace_path(path, newpath, i.arg(2))) {
        size_t size = newpath.size() + 1;
        restore_addr = i.stack() - size;
        std::vector<uint8_t> replaced =
            i.fetch_array((void *)(uintptr_t)restore_addr, size);
        if (replaced.size() != size) {
          after_replace_path(false);
          return block(i, -EBADF);
        }
        restore_data = replaced;
        if (!i.emplace_array((void *)(uintptr_t)restore_addr,
                             std::vector<uint8_t>(newpath.c_str(),
                                                  newpath.c_str() + size))) {
          after_replace_path(false);
          i.emplace_array((void *)(uintptr_t)restore_addr, restore_data);
          restore_data.clear();
          return block(i, -EBADF);
        }
        i.arg(1) = restore_addr;
        i.save();
      }
      return;
    }
#endif
    case SYS_openat: {
      int at = i.arg(1);
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(2), path))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, at, error))
        return block(i, error);
      error = -EPERM;
      if ((i.arg(3) & O_ACCMODE) != O_RDONLY &&
          !can_write_path(path, at, error))
        return block(i, error);

      std::string newpath;
      if (should_replace_path(path, newpath, at, i.arg(3))) {
        size_t size = newpath.size() + 1;
        restore_addr = i.stack() - size;
        std::vector<uint8_t> replaced =
            i.fetch_array((void *)(uintptr_t)restore_addr, size);
        if (replaced.size() != size) {
          after_replace_path(false);
          return block(i, -EBADF);
        }
        restore_data = replaced;
        if (!i.emplace_array((void *)(uintptr_t)restore_addr,
                             std::vector<uint8_t>(newpath.c_str(),
                                                  newpath.c_str() + size))) {
          after_replace_path(false);
          i.emplace_array((void *)(uintptr_t)restore_addr, restore_data);
          restore_data.clear();
          return block(i, -EBADF);
        }
        i.arg(2) = restore_addr;
        i.save();
      }
      return;
    }
    case SYS_fstat: {
      struct stat st;
      if (should_replace_stat("", st, i.arg(1), AT_EMPTY_PATH)) {
        if (!i.emplace_array(
                (void *)i.arg(2),
                std::vector<uint8_t>((char *)&st, (char *)&st + sizeof st)))
          return;
        return block(i, 0);
      }
      return;
    }
#ifdef __x86_64__
    case SYS_stat:
    case SYS_lstat: {
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(1), path))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, AT_FDCWD, error))
        return block(i, error);
      struct stat st;
      if (should_replace_stat(path, st, i.arg(1),
                              i.sysnum() == SYS_lstat ? AT_SYMLINK_NOFOLLOW
                                                       : 0)) {
        if (!i.emplace_array(
                (void *)i.arg(2),
                std::vector<uint8_t>((char *)&st, (char *)&st + sizeof st)))
          return;
        return block(i, 0);
      }
      return;
    }
#endif
    case SYS_execve:
#ifdef __x86_64__
    case SYS_access:
#endif
    case SYS_chdir:
#ifdef __x86_64__
    case SYS_readlink:
#endif
    case SYS_getxattr:
    case SYS_lgetxattr:
    case SYS_statfs:
#ifdef __x86_64__
    case SYS_utimes:
#endif
    {
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(1), path))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, AT_FDCWD, error))
        return block(i, error);
      return;
    }
    case SYS_newfstatat: {
      int at = i.arg(1);
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(2), path))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, at, error))
        return block(i, error);
      struct stat st;
      if (should_replace_stat(path, st, at, i.arg(4))) {
        if (!i.emplace_array(
                (void *)i.arg(2),
                std::vector<uint8_t>((char *)&st, (char *)&st + sizeof st)))
          return;
        return block(i, 0);
      }
      return;
    }
    case SYS_readlinkat:
    case SYS_faccessat:
      // case SYS_execveat:
      {
        int at = i.arg(1);
        std::string path;
        if (!i.fetch_cstr((void *)i.arg(2), path))
          return block(i, -EBADF);
        int error = -ENOENT;
        if (!can_see_path(path, AT_FDCWD, error))
          return block(i, error);
        return;
      }
#ifdef __x86_64__
    case SYS_futimesat:
#endif
    case SYS_utimensat: {
      int at = i.arg(1);
      std::string path;
      if (i.arg(2))
        if (!i.fetch_cstr((void *)i.arg(2), path))
          return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path, at, error))
        return block(i, error);
      error = -EPERM;
      if (!can_write_path(path, at, error))
        return block(i, error);
      return;
    }
    case SYS_truncate:
#ifdef __x86_64__
    case SYS_mkdir:
    case SYS_rmdir:
    case SYS_creat:
    case SYS_unlink:
    case SYS_chmod:
    case SYS_chown:
    case SYS_lchown: {
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(1), path))
        return block(i, -EBADF);
      int error = -EPERM;
      if (!can_write_path(path, AT_FDCWD, error))
        return block(i, error);
      return;
    }
#endif
    case SYS_mkdirat:
    case SYS_fchownat:
    case SYS_unlinkat:
    case SYS_fchmodat: {
      int at = i.arg(1);
      std::string path;
      if (!i.fetch_cstr((void *)i.arg(2), path))
        return block(i, -EBADF);
      int error = -EPERM;
      if (!can_write_path(path, at, error))
        return block(i, error);
      return;
    }
#ifdef __x86_64__
    case SYS_link:
    case SYS_symlink: {
      std::string path1, path2;
      if (!i.fetch_cstr((void *)i.arg(1), path1))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path1, AT_FDCWD, error))
        return block(i, error);
      if (!i.fetch_cstr((void *)i.arg(2), path2))
        return block(i, -EBADF);
      error = -EPERM;
      if (!can_write_path(path2, AT_FDCWD, error))
        return block(i, error);
      return;
    }
    case SYS_rename: {
      std::string path1, path2;
      if (!i.fetch_cstr((void *)i.arg(1), path1))
        return block(i, -EBADF);
      int error = -EPERM;
      if (!can_write_path(path1, AT_FDCWD, error))
        return block(i, error);
      if (!i.fetch_cstr((void *)i.arg(2), path2))
        return block(i, -EBADF);
      error = -EPERM;
      if (!can_write_path(path2, AT_FDCWD, error))
        return block(i, error);
      return;
    }
#endif
    case SYS_linkat:
    case SYS_symlinkat: {
      std::string path1, path2;
      int at1 = i.arg(1);
      if (!i.fetch_cstr((void *)i.arg(2), path1))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path1, at1, error))
        return block(i, error);
      int at2 = i.arg(3);
      if (!i.fetch_cstr((void *)i.arg(4), path2))
        return block(i, -EBADF);
      error = -EPERM;
      if (!can_write_path(path2, at2, error))
        return block(i, error);
      return;
    }
    case SYS_renameat:
    case SYS_renameat2: {
      std::string path1, path2;
      int at1 = i.arg(1);
      if (!i.fetch_cstr((void *)i.arg(2), path1))
        return block(i, -EBADF);
      int error = -ENOENT;
      if (!can_see_path(path1, at1, error))
        return block(i, error);
      int at2 = i.arg(3);
      if (!i.fetch_cstr((void *)i.arg(4), path2))
        return block(i, -EBADF);
      error = -EPERM;
      if (!can_write_path(path2, at2, error))
        return block(i, error);
      return;
    }
    case SYS_clone:
#ifdef __x86_64__
    case SYS_fork:
    case SYS_vfork:
#endif
      if (!can_create_thread(s))
        block(i, -EPERM);
      return;
    case SYS_prlimit64:
      if (i.arg(3))
        block(i, -EPERM);
      return;
    // case SYS_uselib:
    // case SYS_ustat:
    // case SYS_sysfs:
    // case SYS_setpriority:
    // case SYS_sched_setparam:
    // case SYS_sched_setscheduler:
    // case SYS_vhangup:
    // case SYS_modify_ldt:
    // case SYS_pivot_root:
    // case SYS__sysctl:
    // case SYS_prctl:
    // case SYS_adjtimex:
    // case SYS_chroot:
    // case SYS_sync:
    // case SYS_acct:
    // case SYS_settimeofday:
    // case SYS_mount:
    // case SYS_umount2:
    // case SYS_swapon:
    // case SYS_swapoff:
    // case SYS_reboot:
    // case SYS_sethostname:
    // case SYS_setdomainname:
    // case SYS_iopl:
    // case SYS_ioperm:
    // case SYS_create_module:
    // case SYS_init_module:
    // case SYS_delete_module:
    // case SYS_get_kernel_syms:
    // case SYS_query_module:
    // case SYS_quotactl:
    // case SYS_nfsservctl:
    // case SYS_getpmsg:
    // case SYS_putpmsg:
    // case SYS_afs_syscall:
    // case SYS_tuxcall:
    // case SYS_security:
    // case SYS_setxattr:
    // case SYS_lsetxattr:
    // case SYS_fsetxattr:
    // case SYS_listxattr:
    // case SYS_llistxattr:
    // case SYS_flistxattr:
    // case SYS_removexattr:
    // case SYS_lremovexattr:
    // case SYS_fremovexattr:
    // case SYS_sched_setaffinity:
    // case SYS_set_thread_area:
    // case SYS_io_setup:
    // case SYS_io_destroy:
    // case SYS_io_getevents:
    // case SYS_io_submit:
    // case SYS_io_cancel:
    // case SYS_get_thread_area:
    // case SYS_lookup_dcookie:
    // case SYS_remap_file_pages:
    // case SYS_semtimedop:
    // case SYS_clock_settime:
    // case SYS_clock_nanosleep:
    // case SYS_vserver:
    // case SYS_mbind:
    // case SYS_set_mempolicy:
    // case SYS_mq_open:
    // case SYS_mq_unlink:
    // case SYS_mq_timedsend:
    // case SYS_mq_timedreceive:
    // case SYS_mq_notify:
    // case SYS_mq_getsetattr:
    // case SYS_kexec_load:
    // case SYS_waitid:
    // case SYS_add_key:
    // case SYS_request_key:
    // case SYS_keyctl:
    // case SYS_ioprio_set:
    // case SYS_ioprio_get:
    // case SYS_inotify_init:
    // case SYS_inotify_add_watch:
    // case SYS_inotify_rm_watch:
    // case SYS_migrate_pages:
    // case SYS_pselect6:
    // case SYS_unshare:
    // case SYS_sync_file_range:
    // case SYS_vmsplice:
    // case SYS_move_pages:
    // case SYS_signalfd:
    // case SYS_fallocate:
    // case SYS_accept4:
    // case SYS_signalfd4:
    // case SYS_inotify_init1:
    // case SYS_rt_tgsigqueueinfo:
    // case SYS_perf_event_open:
    // case SYS_recvmmsg:
    // case SYS_fanotify_init:
    // case SYS_fanotify_mark:
    // case SYS_name_to_handle_at:
    // case SYS_open_by_handle_at:
    // case SYS_clock_adjtime:
    // case SYS_syncfs:
    // case SYS_sendmmsg:
    // case SYS_setns:
    // case SYS_getcpu:
    // case SYS_process_vm_readv:
    // case SYS_process_vm_writev:
    // case SYS_kcmp:
    // case SYS_finit_module:
    // case SYS_sched_setattr:
    // case SYS_sched_getattr:
    // case SYS_seccomp:
    // case SYS_getrandom:
    // case SYS_memfd_create:
    // case SYS_kexec_file_load:
    // case SYS_bpf:
    // case SYS_userfaultfd:
    // case SYS_membarrier:
    // case SYS_copy_file_range:
    case SYS_shmget:
    case SYS_shmat:
    case SYS_shmctl:
    case SYS_socket:
    case SYS_connect:
    case SYS_accept:
    case SYS_sendto:
    case SYS_recvfrom:
    case SYS_sendmsg:
    case SYS_recvmsg:
    case SYS_shutdown:
    case SYS_bind:
    case SYS_listen:
    case SYS_getsockname:
    case SYS_getpeername:
    case SYS_socketpair:
    case SYS_setsockopt:
    case SYS_getsockopt:
    case SYS_semget:
    case SYS_semop:
    case SYS_semctl:
    case SYS_shmdt:
    case SYS_msgget:
    case SYS_msgsnd:
    case SYS_msgrcv:
    case SYS_msgctl:
    case SYS_ptrace:
    case SYS_syslog:
    case SYS_setuid:
    case SYS_setgid:
    case SYS_setsid:
    case SYS_setreuid:
    case SYS_setregid:
    case SYS_setgroups:
    case SYS_setresuid:
    case SYS_setresgid:
    case SYS_setfsuid:
    case SYS_setfsgid:
    case SYS_capget:
    case SYS_capset:
#ifdef __x86_64__
    case SYS_mknod:
#endif
    case SYS_mlock:
    case SYS_munlock:
    case SYS_mlockall:
    case SYS_munlockall:
    case SYS_mlock2:
    case SYS_mknodat:
      block(i, -EPERM);
      return;
    case SYS_kill:
    case SYS_tkill:
      if (s.find_tid(i.arg(1)) == s.threads.end())
        return block(i, -EPERM);
      else
        return;
    case SYS_tgkill:
      if ((i.arg(1) != -1 && s.find_tid(i.arg(1)) == s.threads.end()) ||
          s.find_tid(i.arg(2)) == s.threads.end())
        return block(i, -EPERM);
      else
        return;
    default:
      printf("Unknown syscall %d\n", i.sysnum());
      block(i, -ENOSYS);
      return;
    }
  }

  virtual void on_syscall_exit(Sandbox<T> &s) {
    SyscallInfo i(*this);
    if (restore_data.size()) {
      i.emplace_array((void *)(uintptr_t)restore_addr, restore_data);
      restore_data.clear();
      after_replace_path(true);
    }
    if (ret_override) {
      i.ret() = ret_val;
      i.save();
      ret_override = false;
    }
    check_startup();
  }
};

#endif
