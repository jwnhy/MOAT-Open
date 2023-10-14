#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "tracepoints.h"

/* Shared Ringbuf for All Events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} pf_rb SEC(".maps");

/* Page Fault User/Kernel */
struct trace_event_page_fault
{
  struct trace_entry ent;
  long unsigned int fault_address;
  long unsigned int ip;
  unsigned int error_code;
  char __data[0];
};

SEC("tracepoint/exceptions/page_fault_user")
int pfu(struct trace_event_page_fault *ctx)
{
  struct pf_event *evt;
  evt = bpf_ringbuf_reserve(&pf_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;
  evt->address = ctx->fault_address;
  evt->error_code = ctx->error_code;
  evt->ip = ctx->ip;
  bpf_snprintf(evt->type, 16, "pfu", NULL, 0);
  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int pfk(struct trace_event_page_fault *ctx)
{
  struct pf_event *evt;
  evt = bpf_ringbuf_reserve(&pf_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;
  evt->address = ctx->fault_address;
  evt->error_code = ctx->error_code;
  evt->ip = ctx->ip;
  bpf_snprintf(evt->type, 16, "pfk", NULL, 0);
  bpf_ringbuf_submit(evt, 0);
  return 0;
}

/* Scheduler Switch */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} sched_rb SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx)
{
  struct switch_event *evt;
  evt = bpf_ringbuf_reserve(&sched_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;
  evt->next_pid = ctx->next_pid;
  evt->next_prio = ctx->next_prio;
  evt->prev_pid = ctx->prev_pid;
  evt->prev_prio = ctx->prev_prio;

  bpf_probe_read_str(&evt->prev_procname, PROCNAME_LEN, (void *)ctx->prev_comm);
  bpf_probe_read_str(&evt->next_procname, PROCNAME_LEN, (void *)ctx->next_comm);
  bpf_ringbuf_submit(evt, 0);
  return 0;
}

/* File Syscalls */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} rw_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_rw_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&rw_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_snprintf(evt->type, 16, "read", NULL, 0);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;
  evt->fd = ctx->args[0];
  evt->buf = ctx->args[1];
  evt->count = ctx->args[2];
  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_rw_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&rw_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_snprintf(evt->type, 16, "write", NULL, 0);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;
  evt->fd = ctx->args[0];
  evt->buf = ctx->args[1];
  evt->count = ctx->args[2];
  bpf_ringbuf_submit(evt, 0);
  return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} open_rb SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_open_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&open_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  //bpf_probe_read_user_str(evt->filename, FILENAME_LEN, (void*)ctx->args[1]);

  evt->dirfd = ctx->args[0];
  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_open_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&open_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  //bpf_probe_read_user_str(evt->filename, FILENAME_LEN, (void*)ctx->args[1]);

  evt->dirfd = ctx->args[0];
  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tp_open(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_open_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&open_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  //bpf_probe_read_user_str(evt->filename, FILENAME_LEN, (void*)ctx->args[1]);

  evt->dirfd = 0;
  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} close_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_close")
int tp_close(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_close_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&close_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;
  evt->fd = ctx->args[0];

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

/* Process Syscalls */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} exec_rb SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_exec_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&exec_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  //bpf_probe_read_user_str(evt->filename, FILENAME_LEN, (void*)ctx->args[0]);

  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
  struct sys_exec_event *evt;
  int host_pid, host_ppid;
  evt = bpf_ringbuf_reserve(&exec_rb, sizeof(*evt), 0);
  if (!evt)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  host_pid = bpf_get_current_pid_tgid() >> 32;
  host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  //bpf_probe_read_user_str(evt->filename, FILENAME_LEN, (void*)ctx->args[1]);

  evt->host_pid = host_pid;
  evt->host_ppid = host_ppid;

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
