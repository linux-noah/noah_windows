#include "test_assert_nolibc.h"

int global_var = 0;

int main()
{
  nr_tests(13);
  global_var = 0xdead;
  int parent_pid = getpid();
  int fork_pid = fork();
  if (fork_pid == 0) {
    assert_true(parent_pid != getpid());
    assert_true(global_var == 0xdead);
    global_var = 0xbeef;
    assert_true(global_var == 0xbeef);
    int gc_pid = fork();
    if (gc_pid == 0) {
      assert_true(global_var == 0xbeef);
      global_var = 0xfeed;
      assert_true(global_var == 0xfeed);
    } else {
      assert_true(global_var == 0xbeef);
      int stat;
      wait4(gc_pid, &stat, 0, 0);
      assert_true(global_var == 0xbeef);
      global_var = 0xb00c;
      assert_true(global_var == 0xb00c);
    }
  } else {
    assert_true(fork_pid > 0);
    assert_true(parent_pid == getpid());
    assert_true(fork_pid != getpid());

    /* Test that memory space of parents and childs are separated */
    int stat;
    wait4(fork_pid, &stat, 0, 0);
    assert_true(global_var == 0xdead);
    global_var = 0xface;
    assert_true(global_var == 0xface);
  }
}

