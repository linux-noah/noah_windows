#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <fcntl.h>

#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <Windows.h>
#include <winsock.h>
#endif

#include "common.h"
#include "noah.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/time.h"
#include "linux/fs.h"


#ifdef _WIN32
DEFINE_SYSCALL(gettimeofday, gaddr_t, tp_ptr, gaddr_t, tzp_ptr)
{
  // TODO: timezone
  struct timeval tp;
  //struct timezone tzp;
  //gettimeofday(&tp, &tzp);


  FILETIME    file_time;
  uint64_t    time;

  GetSystemTimeAsFileTime(&file_time);
  time = file_time.dwLowDateTime;
  time |= static_cast<uint64_t>(file_time.dwHighDateTime) << 32;
  time /= 10;

  static const uint64_t EPOCH = 11644473600000000ULL;
  time -= EPOCH;
  tp.tv_sec = static_cast<long>(time / 1000000ULL);
  tp.tv_usec = static_cast<long>(time % 1000000ULL);

  if (tp_ptr != 0) {
    struct l_timeval l_tp;
    l_tp.tv_sec = tp.tv_sec;
    l_tp.tv_usec = tp.tv_usec;
    if (copy_to_user(tp_ptr, &l_tp, sizeof l_tp))
      return -LINUX_EINVAL;
  }

  /*
  if (tzp_ptr != 0) {
    struct l_timezone l_tzp;
    l_tzp.tz_minuteswest = tzp.tz_minuteswest;
    l_tzp.tz_dsttime = tzp.tz_dsttime;
    if (copy_to_user(tzp_ptr, &l_tzp, sizeof l_tzp))
      return -LINUX_EINVAL;
  }
  */
  return 0;
}
#endif
