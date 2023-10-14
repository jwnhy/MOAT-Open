#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "syscalls.skel.h"

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
	return vfprintf(stderr, fmt, args);
}

int main(void) {
  struct syscalls_bpf *skel;
  int ret;
  libbpf_set_print(print_libbpf_log);
  skel = syscalls_bpf__open_and_load();
  if (!skel)
    return 0;
  ret = syscalls_bpf__attach(skel);
  if (ret) 
    return 0;
  while(1)
    sleep(1);
}
