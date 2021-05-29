#ifndef SANDBOX_H_
#define SANDBOX_H_

#include <algorithm>
#include <list>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/uio.h>
#include <sys/wait.h>
}

class ThreadGone : public std::runtime_error {
public:
  pid_t tid;

  ThreadGone(pid_t tid_) : runtime_error("Thread is gone"), tid(tid_) {}
};

class ThreadData {
public:
  pid_t tid;

  bool had_syscall_entry;
  bool set_opts;

  bool suppress_stop;
  bool unknown;

  inline ThreadData(pid_t tid_)
      : tid(tid_), had_syscall_entry(false), set_opts(false),
        suppress_stop(false), unknown(false) {}

  long ptrace(int, void *, void *);
  bool ptrace_setoptions(int);
  bool ptrace_geteventmsg(unsigned long &);
  bool ptrace_resume(int, int signal = 0);
  bool ptrace_getsiginfo(siginfo_t &);
  bool ptrace_peekdata(void *, long &word);
  bool ptrace_pokedata(void *, long word);
  bool ptrace_getregset(int, struct iovec &);
  bool ptrace_setregset(int, struct iovec &);

  void set_options();
};

template <typename T> class Sandbox;

template <typename T> class Thread : public ThreadData {
public:
  inline Thread(pid_t tid) : ThreadData(tid) {}

  virtual inline void on_syscall_entry(Sandbox<T> &){};
  virtual inline void on_syscall_exit(Sandbox<T> &){};
  virtual inline void on_fork(Sandbox<T> &, pid_t){};
  virtual inline void on_vfork(Sandbox<T> &, pid_t){};
  virtual inline void on_clone(Sandbox<T> &, pid_t){};
  virtual inline void on_exec(Sandbox<T> &){};
  virtual inline void on_exit(Sandbox<T> &, int){};
  virtual inline int on_kill(Sandbox<T> &, int status) {
    return WSTOPSIG(status);
  };
  virtual inline void on_stop(Sandbox<T> &, int){};
};

template <typename T> class Sandbox {
public:
  std::list<T> threads;
  std::list<pid_t> ignore_once;

  typename std::list<T>::iterator thread_add(pid_t);
  typename std::list<T>::iterator find_tid(pid_t);

  void event_loop();
  pid_t spawn_process(char const *, int, char const *const *, void (*)());
  static bool ptrace_traceme();
};

void panic(std::string);
void panic_errno(std::string);

template <typename T>
typename std::list<T>::iterator Sandbox<T>::thread_add(pid_t tid) {
  T th(tid);
  return threads.insert(threads.end(), tid);
}

template <typename T>
typename std::list<T>::iterator Sandbox<T>::find_tid(pid_t tid) {
  typename std::list<T>::iterator i = threads.begin();
  for (typename std::list<T>::iterator end = threads.end(); i != end; i++)
    if (i->tid == tid)
      return i;
  return i;
}

template <typename T> bool Sandbox<T>::ptrace_traceme() {
  if (ptrace(PTRACE_TRACEME))
    return false;
  return true;
}

template <typename T>
pid_t Sandbox<T>::spawn_process(char const *path, int argc,
                                char const *const *argv, void (*hook)()) {
  char const **args = new char const *[argc + 1];
  for (int i = 0; i < argc; i++)
    args[i] = argv[i];
  args[argc] = NULL;
  pid_t pid = fork();
  if (pid < 0)
    panic_errno("fork");
  if (!pid) {
    if (!ptrace_traceme())
      panic_errno("ptrace TRACEME");
    if (hook)
      hook();
    execvp(path, (char **)args);
    panic_errno("execvp");
    return -1;
  } else {
    delete[] args;
    T &init = *thread_add(pid);
    init.had_syscall_entry = true;
    init.suppress_stop = true;
    return pid;
  }
}

template <typename T> void Sandbox<T>::event_loop() {
  while (threads.size()) {
    int status;
    pid_t tid = waitpid(-1, &status, __WALL);
    if (tid < 0) {
      if (errno == ECHILD)
        break;
      panic_errno("wait");
    }

    typename std::list<pid_t>::iterator ign =
        std::find(ignore_once.begin(), ignore_once.end(), tid);
    if (ign != ignore_once.end()) {
      ignore_once.erase(ign);
      continue;
    }

    typename std::list<T>::iterator th = find_tid(tid);
    if (th == threads.end()) {
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        T &unkth = *thread_add(tid);
        unkth.unknown = true;
      } else {
        panic("Got unexpected notification for thread tid");
      }
    } else {
      try {
        if (th->unknown)
          panic("Got notification for unknown thread");
        th->set_options();
        if (WIFEXITED(status)) {
          try {
            th->on_exit(*this, status);
          } catch (const ThreadGone &e) {
          }
          threads.erase(th);
        } else if (WIFSIGNALED(status)) {
          try {
            th->on_exit(*this, status);
          } catch (const ThreadGone &e) {
          }
          threads.erase(th);
        } else if (WIFSTOPPED(status)) {
          siginfo_t info;
          info.si_code = 123;
          if (!th->ptrace_getsiginfo(info))
            if (errno != EINVAL)
              panic_errno("ptrace GETSIGINFO");
          bool group_stop = !!errno;
          if (WSTOPSIG(status) == SIGTRAP && !errno &&
              (th->suppress_stop || (info.si_code & 0xFF) == SIGTRAP)) {
            int event = status >> 16;
            if (!event) {
              if (th->had_syscall_entry) {
                th->had_syscall_entry = false;
                try {
                  th->on_syscall_exit(*this);
                } catch (const ThreadGone &e) {
                  if (e.tid == tid)
                    throw;
                }
              } else {
                th->had_syscall_entry = true;
                try {
                  th->on_syscall_entry(*this);
                } catch (const ThreadGone &e) {
                  if (e.tid == tid)
                    throw;
                }
              }
            } else if (event == PTRACE_EVENT_CLONE ||
                       event == PTRACE_EVENT_FORK ||
                       event == PTRACE_EVENT_VFORK) {
              unsigned long newtid;
              if (!th->ptrace_geteventmsg(newtid))
                panic_errno("ptrace GETEVENTMSG");
              typename std::list<T>::iterator unkth = find_tid(newtid);
              if (unkth == threads.end()) {
                T &newth = *thread_add(newtid);
                newth.suppress_stop = true;
              } else {
                if (!unkth->unknown)
                  panic("clone produced a known thread");
                unkth->unknown = false;
                try {
                  if (!unkth->ptrace_resume(PTRACE_SYSCALL))
                    panic_errno("ptrace SYSCALL");
                } catch (const ThreadGone &e) {
                }
              }
              try {
                if (event == PTRACE_EVENT_CLONE)
                  th->on_clone(*this, newtid);
                else if (event == PTRACE_EVENT_FORK)
                  th->on_fork(*this, newtid);
                else
                  th->on_vfork(*this, newtid);
              } catch (const ThreadGone &e) {
                if (e.tid == tid)
                  throw;
              }
            } else if (event == PTRACE_EVENT_EXEC) {
              try {
                th->on_exec(*this);
              } catch (const ThreadGone &e) {
                if (e.tid == tid)
                  throw;
              }
            } else {
              fprintf(stderr, "%d Unknown event %d\n", tid, event);
            }
            if (!th->ptrace_resume(PTRACE_SYSCALL))
              panic_errno("ptrace SYSCALL");
            th->suppress_stop = false;
          } else if (WSTOPSIG(status) == SIGSTOP && th->suppress_stop) {
            if (!th->ptrace_resume(PTRACE_SYSCALL))
              panic_errno("ptrace SYSCALL");
            th->suppress_stop = false;
          } else {
            try {
              if (group_stop) {
                th->on_stop(*this, status);
                if (!th->ptrace_resume(PTRACE_LISTEN))
                  panic_errno("ptrace LISTEN");
              } else {
                if (!th->ptrace_resume(PTRACE_SYSCALL,
                                       th->on_kill(*this, status)))
                  panic_errno("ptrace SYSCALL");
              }
            } catch (const ThreadGone &e) {
              if (e.tid == tid)
                throw;
            }
          }
        }
      } catch (const ThreadGone &e) {
        continue;
      }
    }
  }
}
#endif
