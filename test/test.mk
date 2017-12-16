TEST_UPROGS := \
	$(addprefix test_assertion/build/, fib test_fork test_thread test_execve test_execve2 test_sigprocmask test_sigaction test_sigaltstack)\
	$(addprefix test_stdout/build/, hello hello_static hello_nolibc cat echo)\
	$(addprefix test_shell/build/, mv env gcc)

LINUX_BUILD_SERV ?= idylls.jp

test: $(TEST_UPROGS)

test_stdout/build/hello_static: test_stdout/hello.c include/*.h
	CFLAGS=--static;\
	$(MAKE_TEST_UPROGS)
test_stdout/build/hello_nolibc: test_stdout/hello_nolibc.c include/noah.S include/*.h
	CFLAGS="--static -nostdlib";\
	$(MAKE_TEST_UPROGS)

test_assertion/build/%: test_assertion/%.c include/*.h
	CFLAGS=-lpthread;\
	$(MAKE_TEST_UPROGS)
test_stdout/build/%: test_stdout/%.c include/*.h
	CFLAGS=-lpthread;\
	$(MAKE_TEST_UPROGS)
test_shell/build/%: test_shell/%.c include/*.h
	CFLAGS=-lpthread;\
	$(MAKE_TEST_UPROGS)

ifeq ($(OS),Windows_NT)
  PLATFORM = Windows
else
  PLATFORM = $(shell uname)
endif

ifeq ($(PLATFORM),Linux)
  MAKE_TEST_UPROGS = $(MAKE_TEST_LOCAL)
else
  MAKE_TEST_UPROGS = $(MAKE_TEST_REMOTE)
endif

MAKE_TEST_LOCAL = gcc -std=gnu99 -g -O0 $^ $${CFLAGS} -o $@

MAKE_TEST_REMOTE = ssh $(LINUX_BUILD_SERV) "rm /tmp/$(USER)/*";\
                   rsync $^ $(LINUX_BUILD_SERV):/tmp/$(USER)/;\
                   ssh $(LINUX_BUILD_SERV) "gcc -std=gnu99 -g -O0 /tmp/$(USER)/$*.c $${CFLAGS} -o /tmp/$(USER)/$*";\
                   rsync $(LINUX_BUILD_SERV):/tmp/$(USER)/$* $@

clean:
	$(RM) test_assertion/build/* test_stdout/build/*
	$(RM) `ls test_shell/build/* | grep -v gcc`

.PHONY: test clean
