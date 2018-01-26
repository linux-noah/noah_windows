#include "test_assert_nolibc.h"

int global_var = 0;

int main()
{
  nr_tests(8);
  global_var = 0xdead;
  int parent_pid = getpid();
  int fork_pid = fork();
  if (fork_pid == 0) {
    assert_true(parent_pid != getpid());
    assert_true(global_var == 0xdead);
    global_var = 0xbeef;
    assert_true(global_var == 0xbeef);
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

