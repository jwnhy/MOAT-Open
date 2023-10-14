#ifndef __TRACEPOINTS_H__
#define __TRACEPOINTS_H__
struct pf_event {
  unsigned long address;
  unsigned long error_code;
  unsigned long ip;
  char type[16];
};

#define PROCNAME_LEN 16
struct switch_event {
  int prev_pid;
  int prev_prio;
  char prev_procname[PROCNAME_LEN];
  int next_pid;
  int next_prio;
  char next_procname[PROCNAME_LEN];
};

struct sys_rw_event {
  int host_pid;
  int host_ppid;
  char comm[PROCNAME_LEN];
  char type[16];
  unsigned long fd;
  unsigned long buf;
  unsigned long count;
};

#define FILENAME_LEN 64
struct sys_open_event {
  int host_pid;
  int host_ppid;
  char comm[PROCNAME_LEN];
  int dirfd;
  char filename[FILENAME_LEN];
};

struct sys_close_event {
  int host_pid;
  int host_ppid;
  char comm[PROCNAME_LEN];
  int fd;
};

struct sys_exec_event {
  int host_pid;
  int host_ppid;
  char comm[PROCNAME_LEN];
  char filename[FILENAME_LEN];
};

#endif
