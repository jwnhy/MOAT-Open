#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve0(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve1(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve2(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve3(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve4(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve5(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve6(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve7(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve8(void *ctx)
{ return 0; }
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve9(void *ctx)
{ return 0; }
