#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <cerrno>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <pthread.h>
#include <stdnoreturn.h>
#include <execinfo.h>
#endif

#include "noah.h"
#include "cross_platform.h"
#include "vm.h"
#include "linux/time.h"
#include "linux/fs.h"

static FILE *printk_sink, *warnk_sink;
pthread_mutex_t printk_sync = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t warnk_sync = PTHREAD_MUTEX_INITIALIZER;

#ifdef _WIN32
static int
vasprintf(char **out, const char *fmt, va_list ap)
{
  int len = _vscprintf(fmt, ap);
  *out = (char *)malloc(len);
  if (out == NULL) {
    return -1;
  }
  return vsprintf_s(*out, len, fmt, ap);
}

static int
asprintf(char **out, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, out);
  int ret = vasprintf(out, fmt, ap);
  va_end(ap);
  return ret;
}
#endif

void
init_sink(const char *fn, FILE **sinkp, const char *name)
{
  if (! fn) {
    fn = "/dev/null";
  }
  // *sinkp = fdopen(vkern_dup_fd(fd, false), "w");
  *sinkp = fopen(name, "w");

  char buf[1000];
  time_t now = time(0);
  struct tm tm = *gmtime(&now);
  strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);
  fprintf(*sinkp, "\n//==================\n");
  fprintf(*sinkp, "%s log started: [%s]\n", name, buf);
  fflush(*sinkp);
}

void
print_to_sink(FILE *sink, pthread_mutex_t *sync, const char *mes)
{
  if (!sink) {
    return;
  }

  uint64_t tid = 0;
  pthread_threadid_np(NULL, &tid);

  if (sync) {
    pthread_mutex_lock(sync);
  }
  fprintf(sink, "[%d:%lld] %s", getpid(), tid, mes);
  fflush(sink);
  if (sync) {
    pthread_mutex_unlock(sync);
  }
}

void
init_printk(const char *fn)
{
  init_sink(fn, &printk_sink, "printk");
}

void
printk(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char *mes;

  if (!printk_sink) {
    va_end(ap);
    return;
  }

  vasprintf(&mes, fmt, ap);
  print_to_sink(printk_sink, &printk_sync, mes);

  free(mes);
  va_end(ap);
}

void
init_warnk(const char *fn)
{
  init_sink(fn, &warnk_sink, "warning");
}

void
warnk(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char *mes;

  vasprintf(&mes, fmt, ap);

  printk("WARNING: %s", mes);
  print_to_sink(warnk_sink, &printk_sync, mes);

#ifndef NDEBUG
  //const char *magenda = "\x1b[35m", *reset = "\x1b[0m";
  //fprintf(stderr, "%sNoah WARNING: %s%s", magenda, mes, reset);
#endif

  free(mes);
  va_end(ap);
}

static void
printbt_to_sink(FILE *sink, pthread_mutex_t *sync)
{
#ifdef __APPLE__
  if (!sink) {
    return;
  }

  void *array[10];
  size_t size;
  char **strings;
  size_t i;
  uint64_t tid = 0;

  pthread_threadid_np(NULL, &tid);
  size = backtrace(array, 10);
  strings = backtrace_symbols(array, size);

  if (sync) {
    pthread_mutex_lock(sync);
  }
  fprintf(sink, "[%d:%lld] Obtained %zd stack frames.\n", getpid(), tid, size);
  for(i = 0; i < size; i++)
    fprintf(sink, "%s\n", strings[i]);
  fflush(sink);
  if (sync) {
    pthread_mutex_unlock(sync);
  }

  free(strings);
#endif
}

noreturn void
panic(const char *fmt, ...)
{
  int err = errno;
  va_list ap, cp;
  va_start(ap, fmt);
  va_copy(cp, ap);
  char *given, *mes;

  vasprintf(&given, fmt, ap);
  asprintf(&mes, "!!PANIC!!\nperror is \"%s\" if it is valid\n%s\n", strerror(err), given);

  printk("!!PANIC!!%s", mes);
  printbt_to_sink(printk_sink, &printk_sync);

  print_to_sink(warnk_sink, &warnk_sync, mes);
  printbt_to_sink(warnk_sink, &warnk_sync);

  const char *magenda = "\x1b[35m", *reset = "\x1b[0m";
  fprintf(stderr, "%s%s", magenda, mes);
  printbt_to_sink(stderr, NULL);
  fprintf(stderr, "%s\n", reset);

  free(given);
  free(mes);

#ifdef __APPLE__
  struct rlimit lim;
  getrlimit(RLIMIT_CORE, &lim);
  if (lim.rlim_cur == 0) {
    fprintf(stderr, "%sSet the ulimit value to unlimited to generate the coredump? [Y/n] %s", magenda, reset);
    char ans = getchar();
    if (ans == '\n' || ans == '\r' || ans == 'Y' || ans == 'y') {
      lim.rlim_cur = RLIM_INFINITY;
      lim.rlim_max = RLIM_INFINITY;
      setrlimit(RLIMIT_CORE, &lim);
    }
  }
#endif
  
  fprintf(stderr, "%saborting..%s\n", magenda, reset);
  //die_with_forcedsig(LINUX_SIGABRT);
  abort();
}
