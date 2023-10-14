#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "tracepoints.skel.h"
#include "tracepoints.h"

#define DISCARD

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
	return vfprintf(stderr, fmt, args);
}

int discard(void *ctx, void *data, size_t data_sz) {
  return 0;
}

int handle_sw_evt(void *ctx, void *data, size_t data_sz) {
  const struct switch_event *e = data;
  printf("%-16s %-7d %-16s %-7d\n", e->prev_procname, e->prev_pid, e->next_procname, e->next_pid);
  return 0;
}

int handle_pf_evt(void *ctx, void *data, size_t data_sz) {
  const struct pf_event *e = data;
  printf("%-7s %-16lx %-16lx %-7ld\n", e->type, e->address, e->ip, e->error_code);
  return 0;
}

int handle_rw_evt(void *ctx, void *data, size_t data_sz) {
  const struct sys_rw_event *e = data;
  printf("%-7s %-16s %-8d %-8d %-7ld\n", e->type, e->comm, e->host_pid, e->host_ppid, e->fd);
  return 0;
}

int handle_open_evt(void *ctx, void *data, size_t data_sz) {
  const struct sys_open_event *e = data;
  printf("%-16s %-8d %-8d %-7d %s\n", e->comm, e->host_pid, e->host_ppid, e->dirfd, e->filename);
  return 0;
}

int handle_close_evt(void *ctx, void *data, size_t data_sz) {
  const struct sys_close_event *e = data;
  printf("%-16s %-8d %-8d %-7d\n", e->comm, e->host_pid, e->host_ppid, e->fd);
  return 0;
}

int handle_exec_evt(void *ctx, void *data, size_t data_sz) {
  const struct sys_exec_event *e = data;
  printf("%-16s %-8d %-8d %s\n", e->comm, e->host_pid, e->host_ppid, e->filename);
  return 0;
}


int main(void) {
  struct tracepoints_bpf *skel;
  int ret;
  libbpf_set_print(print_libbpf_log);
  skel = tracepoints_bpf__open_and_load();
  if (!skel)
    return 0;
  ret = tracepoints_bpf__attach(skel);
  if (ret) 
    return 0;
#ifndef DISCARD
  struct ring_buffer* rbs[] = {
    //ring_buffer__new(bpf_map__fd(skel->maps.sched_rb), handle_sw_evt, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.pf_rb), handle_pf_evt, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.rw_rb), handle_rw_evt, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.open_rb), handle_open_evt, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.close_rb), handle_close_evt, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.exec_rb), handle_exec_evt, NULL, NULL),
  };
#else
  struct ring_buffer* rbs[] = {
    //ring_buffer__new(bpf_map__fd(skel->maps.sched_rb), discard, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.pf_rb), discard, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.rw_rb), discard, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.open_rb), discard, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.close_rb), discard, NULL, NULL),
    ring_buffer__new(bpf_map__fd(skel->maps.exec_rb), discard, NULL, NULL),
  };
#endif
  while(1) {
    int n = sizeof(rbs) / sizeof(rbs[0]);
    for (int i = 0; i < n; i++)
      ring_buffer__poll(rbs[i], 100);
  }
}
