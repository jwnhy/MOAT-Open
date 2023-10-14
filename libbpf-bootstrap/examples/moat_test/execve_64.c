#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "execve_64.skel.h"

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
	return vfprintf(stderr, fmt, args);
}

int main(void) {
  struct execve_64_bpf *skel;
  int ret;
  libbpf_set_print(print_libbpf_log);
  skel = execve_64_bpf__open_and_load();
  if (!skel)
    return 0;
  ret = execve_64_bpf__attach(skel);
  if (ret) 
    return 0;
  while(1)
    sleep(1);
}
