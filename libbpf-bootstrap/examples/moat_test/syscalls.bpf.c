#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("tp/syscalls/sys_exit_arch_prctl")
int handle_sys_exit_arch_prctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_arch_prctl")
int handle_sys_enter_arch_prctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigreturn")
int handle_sys_exit_rt_sigreturn(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigreturn")
int handle_sys_enter_rt_sigreturn(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_iopl")
int handle_sys_exit_iopl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_iopl")
int handle_sys_enter_iopl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ioperm")
int handle_sys_exit_ioperm(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ioperm")
int handle_sys_enter_ioperm(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_modify_ldt")
int handle_sys_exit_modify_ldt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_modify_ldt")
int handle_sys_enter_modify_ldt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mmap")
int handle_sys_exit_mmap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mmap")
int handle_sys_enter_mmap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_unshare")
int handle_sys_exit_unshare(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_unshare")
int handle_sys_enter_unshare(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clone3")
int handle_sys_exit_clone3(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clone3")
int handle_sys_enter_clone3(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clone")
int handle_sys_exit_clone(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clone")
int handle_sys_enter_clone(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_vfork")
int handle_sys_exit_vfork(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_vfork")
int handle_sys_enter_vfork(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fork")
int handle_sys_exit_fork(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fork")
int handle_sys_enter_fork(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_set_tid_address")
int handle_sys_exit_set_tid_address(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_set_tid_address")
int handle_sys_enter_set_tid_address(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_personality")
int handle_sys_exit_personality(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_personality")
int handle_sys_enter_personality(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_wait4")
int handle_sys_exit_wait4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_wait4")
int handle_sys_enter_wait4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_waitid")
int handle_sys_exit_waitid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_waitid")
int handle_sys_enter_waitid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_exit_group")
int handle_sys_exit_exit_group(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_exit_group")
int handle_sys_enter_exit_group(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_exit")
int handle_sys_exit_exit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_exit")
int handle_sys_enter_exit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_capset")
int handle_sys_exit_capset(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_capset")
int handle_sys_enter_capset(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_capget")
int handle_sys_exit_capget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_capget")
int handle_sys_enter_capget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ptrace")
int handle_sys_exit_ptrace(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ptrace")
int handle_sys_enter_ptrace(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigsuspend")
int handle_sys_exit_rt_sigsuspend(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigsuspend")
int handle_sys_enter_rt_sigsuspend(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pause")
int handle_sys_exit_pause(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pause")
int handle_sys_enter_pause(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigaction")
int handle_sys_exit_rt_sigaction(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigaction")
int handle_sys_enter_rt_sigaction(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sigaltstack")
int handle_sys_exit_sigaltstack(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sigaltstack")
int handle_sys_enter_sigaltstack(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_tgsigqueueinfo")
int handle_sys_exit_rt_tgsigqueueinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_tgsigqueueinfo")
int handle_sys_enter_rt_tgsigqueueinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigqueueinfo")
int handle_sys_exit_rt_sigqueueinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigqueueinfo")
int handle_sys_enter_rt_sigqueueinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_tkill")
int handle_sys_exit_tkill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_tkill")
int handle_sys_enter_tkill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_tgkill")
int handle_sys_exit_tgkill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_tgkill")
int handle_sys_enter_tgkill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pidfd_send_signal")
int handle_sys_exit_pidfd_send_signal(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pidfd_send_signal")
int handle_sys_enter_pidfd_send_signal(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_kill")
int handle_sys_exit_kill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_kill")
int handle_sys_enter_kill(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigtimedwait")
int handle_sys_exit_rt_sigtimedwait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigtimedwait")
int handle_sys_enter_rt_sigtimedwait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigpending")
int handle_sys_exit_rt_sigpending(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigpending")
int handle_sys_enter_rt_sigpending(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rt_sigprocmask")
int handle_sys_exit_rt_sigprocmask(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rt_sigprocmask")
int handle_sys_enter_rt_sigprocmask(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_restart_syscall")
int handle_sys_exit_restart_syscall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_restart_syscall")
int handle_sys_enter_restart_syscall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sysinfo")
int handle_sys_exit_sysinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sysinfo")
int handle_sys_enter_sysinfo(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getcpu")
int handle_sys_exit_getcpu(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getcpu")
int handle_sys_enter_getcpu(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_prctl")
int handle_sys_exit_prctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_prctl")
int handle_sys_enter_prctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_umask")
int handle_sys_exit_umask(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_umask")
int handle_sys_enter_umask(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getrusage")
int handle_sys_exit_getrusage(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getrusage")
int handle_sys_enter_getrusage(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setrlimit")
int handle_sys_exit_setrlimit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setrlimit")
int handle_sys_enter_setrlimit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_prlimit64")
int handle_sys_exit_prlimit64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_prlimit64")
int handle_sys_enter_prlimit64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getrlimit")
int handle_sys_exit_getrlimit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getrlimit")
int handle_sys_enter_getrlimit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setdomainname")
int handle_sys_exit_setdomainname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setdomainname")
int handle_sys_enter_setdomainname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sethostname")
int handle_sys_exit_sethostname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sethostname")
int handle_sys_enter_sethostname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_newuname")
int handle_sys_exit_newuname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_newuname")
int handle_sys_enter_newuname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setsid")
int handle_sys_exit_setsid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setsid")
int handle_sys_enter_setsid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getsid")
int handle_sys_exit_getsid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getsid")
int handle_sys_enter_getsid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getpgrp")
int handle_sys_exit_getpgrp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getpgrp")
int handle_sys_enter_getpgrp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getpgid")
int handle_sys_exit_getpgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getpgid")
int handle_sys_enter_getpgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setpgid")
int handle_sys_exit_setpgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setpgid")
int handle_sys_enter_setpgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_times")
int handle_sys_exit_times(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_times")
int handle_sys_enter_times(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getegid")
int handle_sys_exit_getegid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getegid")
int handle_sys_enter_getegid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getgid")
int handle_sys_exit_getgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getgid")
int handle_sys_enter_getgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_geteuid")
int handle_sys_exit_geteuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_geteuid")
int handle_sys_enter_geteuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getuid")
int handle_sys_exit_getuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getuid")
int handle_sys_enter_getuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getppid")
int handle_sys_exit_getppid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getppid")
int handle_sys_enter_getppid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_gettid")
int handle_sys_exit_gettid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_gettid")
int handle_sys_enter_gettid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getpid")
int handle_sys_exit_getpid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getpid")
int handle_sys_enter_getpid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setfsgid")
int handle_sys_exit_setfsgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setfsgid")
int handle_sys_enter_setfsgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setfsuid")
int handle_sys_exit_setfsuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setfsuid")
int handle_sys_enter_setfsuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getresgid")
int handle_sys_exit_getresgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getresgid")
int handle_sys_enter_getresgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setresgid")
int handle_sys_exit_setresgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setresgid")
int handle_sys_enter_setresgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getresuid")
int handle_sys_exit_getresuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getresuid")
int handle_sys_enter_getresuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setresuid")
int handle_sys_exit_setresuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setresuid")
int handle_sys_enter_setresuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setuid")
int handle_sys_exit_setuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setuid")
int handle_sys_enter_setuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setreuid")
int handle_sys_exit_setreuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setreuid")
int handle_sys_enter_setreuid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setgid")
int handle_sys_exit_setgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setgid")
int handle_sys_enter_setgid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setregid")
int handle_sys_exit_setregid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setregid")
int handle_sys_enter_setregid(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getpriority")
int handle_sys_exit_getpriority(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getpriority")
int handle_sys_enter_getpriority(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setpriority")
int handle_sys_exit_setpriority(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setpriority")
int handle_sys_enter_setpriority(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pidfd_getfd")
int handle_sys_exit_pidfd_getfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pidfd_getfd")
int handle_sys_enter_pidfd_getfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pidfd_open")
int handle_sys_exit_pidfd_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pidfd_open")
int handle_sys_enter_pidfd_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setns")
int handle_sys_exit_setns(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setns")
int handle_sys_enter_setns(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_reboot")
int handle_sys_exit_reboot(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_reboot")
int handle_sys_enter_reboot(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setgroups")
int handle_sys_exit_setgroups(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setgroups")
int handle_sys_enter_setgroups(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getgroups")
int handle_sys_exit_getgroups(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getgroups")
int handle_sys_enter_getgroups(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_rr_get_interval")
int handle_sys_exit_sched_rr_get_interval(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_rr_get_interval")
int handle_sys_enter_sched_rr_get_interval(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_get_priority_min")
int handle_sys_exit_sched_get_priority_min(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_get_priority_min")
int handle_sys_enter_sched_get_priority_min(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_get_priority_max")
int handle_sys_exit_sched_get_priority_max(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_get_priority_max")
int handle_sys_enter_sched_get_priority_max(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_yield")
int handle_sys_exit_sched_yield(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_yield")
int handle_sys_enter_sched_yield(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_getaffinity")
int handle_sys_exit_sched_getaffinity(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_getaffinity")
int handle_sys_enter_sched_getaffinity(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_setaffinity")
int handle_sys_exit_sched_setaffinity(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_setaffinity")
int handle_sys_enter_sched_setaffinity(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_getattr")
int handle_sys_exit_sched_getattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_getattr")
int handle_sys_enter_sched_getattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_getparam")
int handle_sys_exit_sched_getparam(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_getparam")
int handle_sys_enter_sched_getparam(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_getscheduler")
int handle_sys_exit_sched_getscheduler(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_getscheduler")
int handle_sys_enter_sched_getscheduler(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_setattr")
int handle_sys_exit_sched_setattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_setattr")
int handle_sys_enter_sched_setattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_setparam")
int handle_sys_exit_sched_setparam(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_setparam")
int handle_sys_enter_sched_setparam(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sched_setscheduler")
int handle_sys_exit_sched_setscheduler(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sched_setscheduler")
int handle_sys_enter_sched_setscheduler(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_membarrier")
int handle_sys_exit_membarrier(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_membarrier")
int handle_sys_enter_membarrier(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_syslog")
int handle_sys_exit_syslog(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_syslog")
int handle_sys_enter_syslog(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_finit_module")
int handle_sys_exit_finit_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_finit_module")
int handle_sys_enter_finit_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_init_module")
int handle_sys_exit_init_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_init_module")
int handle_sys_enter_init_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_delete_module")
int handle_sys_exit_delete_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_delete_module")
int handle_sys_enter_delete_module(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_kcmp")
int handle_sys_exit_kcmp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_kcmp")
int handle_sys_enter_kcmp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_adjtimex")
int handle_sys_exit_adjtimex(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_adjtimex")
int handle_sys_enter_adjtimex(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_settimeofday")
int handle_sys_exit_settimeofday(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_settimeofday")
int handle_sys_enter_settimeofday(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_gettimeofday")
int handle_sys_exit_gettimeofday(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_gettimeofday")
int handle_sys_enter_gettimeofday(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_time")
int handle_sys_exit_time(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_time")
int handle_sys_enter_time(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_nanosleep")
int handle_sys_exit_nanosleep(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_nanosleep")
int handle_sys_enter_nanosleep(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clock_nanosleep")
int handle_sys_exit_clock_nanosleep(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clock_nanosleep")
int handle_sys_enter_clock_nanosleep(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clock_getres")
int handle_sys_exit_clock_getres(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clock_getres")
int handle_sys_enter_clock_getres(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clock_adjtime")
int handle_sys_exit_clock_adjtime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clock_adjtime")
int handle_sys_enter_clock_adjtime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clock_gettime")
int handle_sys_exit_clock_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clock_gettime")
int handle_sys_enter_clock_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_clock_settime")
int handle_sys_exit_clock_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_clock_settime")
int handle_sys_enter_clock_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timer_delete")
int handle_sys_exit_timer_delete(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timer_delete")
int handle_sys_enter_timer_delete(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timer_settime")
int handle_sys_exit_timer_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timer_settime")
int handle_sys_enter_timer_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timer_getoverrun")
int handle_sys_exit_timer_getoverrun(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timer_getoverrun")
int handle_sys_enter_timer_getoverrun(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timer_gettime")
int handle_sys_exit_timer_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timer_gettime")
int handle_sys_enter_timer_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timer_create")
int handle_sys_exit_timer_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timer_create")
int handle_sys_enter_timer_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setitimer")
int handle_sys_exit_setitimer(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setitimer")
int handle_sys_enter_setitimer(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_alarm")
int handle_sys_exit_alarm(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_alarm")
int handle_sys_enter_alarm(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getitimer")
int handle_sys_exit_getitimer(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getitimer")
int handle_sys_enter_getitimer(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_futex_waitv")
int handle_sys_exit_futex_waitv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_futex_waitv")
int handle_sys_enter_futex_waitv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_futex")
int handle_sys_exit_futex(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_futex")
int handle_sys_enter_futex(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_get_robust_list")
int handle_sys_exit_get_robust_list(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_get_robust_list")
int handle_sys_enter_get_robust_list(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_set_robust_list")
int handle_sys_exit_set_robust_list(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_set_robust_list")
int handle_sys_enter_set_robust_list(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_acct")
int handle_sys_exit_acct(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_acct")
int handle_sys_enter_acct(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_kexec_load")
int handle_sys_exit_kexec_load(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_kexec_load")
int handle_sys_enter_kexec_load(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_seccomp")
int handle_sys_exit_seccomp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_seccomp")
int handle_sys_enter_seccomp(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_bpf")
int handle_sys_exit_bpf(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_bpf")
int handle_sys_enter_bpf(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_perf_event_open")
int handle_sys_exit_perf_event_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_perf_event_open")
int handle_sys_enter_perf_event_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rseq")
int handle_sys_exit_rseq(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rseq")
int handle_sys_enter_rseq(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_process_mrelease")
int handle_sys_exit_process_mrelease(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_process_mrelease")
int handle_sys_enter_process_mrelease(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fadvise64")
int handle_sys_exit_fadvise64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fadvise64")
int handle_sys_enter_fadvise64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_readahead")
int handle_sys_exit_readahead(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_readahead")
int handle_sys_enter_readahead(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mincore")
int handle_sys_exit_mincore(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mincore")
int handle_sys_enter_mincore(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_munlockall")
int handle_sys_exit_munlockall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_munlockall")
int handle_sys_enter_munlockall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mlockall")
int handle_sys_exit_mlockall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mlockall")
int handle_sys_enter_mlockall(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_munlock")
int handle_sys_exit_munlock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_munlock")
int handle_sys_enter_munlock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mlock2")
int handle_sys_exit_mlock2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mlock2")
int handle_sys_enter_mlock2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mlock")
int handle_sys_exit_mlock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mlock")
int handle_sys_enter_mlock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_remap_file_pages")
int handle_sys_exit_remap_file_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_remap_file_pages")
int handle_sys_enter_remap_file_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_munmap")
int handle_sys_exit_munmap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_munmap")
int handle_sys_enter_munmap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_brk")
int handle_sys_exit_brk(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_brk")
int handle_sys_enter_brk(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pkey_free")
int handle_sys_exit_pkey_free(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pkey_free")
int handle_sys_enter_pkey_free(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pkey_alloc")
int handle_sys_exit_pkey_alloc(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pkey_alloc")
int handle_sys_enter_pkey_alloc(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pkey_mprotect")
int handle_sys_exit_pkey_mprotect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pkey_mprotect")
int handle_sys_enter_pkey_mprotect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mprotect")
int handle_sys_exit_mprotect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mprotect")
int handle_sys_enter_mprotect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mremap")
int handle_sys_exit_mremap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mremap")
int handle_sys_enter_mremap(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_msync")
int handle_sys_exit_msync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_msync")
int handle_sys_enter_msync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_process_vm_writev")
int handle_sys_exit_process_vm_writev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_process_vm_writev")
int handle_sys_enter_process_vm_writev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_process_vm_readv")
int handle_sys_exit_process_vm_readv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_process_vm_readv")
int handle_sys_enter_process_vm_readv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_process_madvise")
int handle_sys_exit_process_madvise(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_process_madvise")
int handle_sys_enter_process_madvise(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_madvise")
int handle_sys_exit_madvise(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_madvise")
int handle_sys_enter_madvise(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_swapon")
int handle_sys_exit_swapon(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_swapon")
int handle_sys_enter_swapon(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_swapoff")
int handle_sys_exit_swapoff(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_swapoff")
int handle_sys_enter_swapoff(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_get_mempolicy")
int handle_sys_exit_get_mempolicy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_get_mempolicy")
int handle_sys_enter_get_mempolicy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_migrate_pages")
int handle_sys_exit_migrate_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_migrate_pages")
int handle_sys_enter_migrate_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_set_mempolicy")
int handle_sys_exit_set_mempolicy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_set_mempolicy")
int handle_sys_enter_set_mempolicy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mbind")
int handle_sys_exit_mbind(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mbind")
int handle_sys_enter_mbind(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_set_mempolicy_home_node")
int handle_sys_exit_set_mempolicy_home_node(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_set_mempolicy_home_node")
int handle_sys_enter_set_mempolicy_home_node(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_move_pages")
int handle_sys_exit_move_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_move_pages")
int handle_sys_enter_move_pages(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_memfd_secret")
int handle_sys_exit_memfd_secret(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_memfd_secret")
int handle_sys_enter_memfd_secret(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_memfd_create")
int handle_sys_exit_memfd_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_memfd_create")
int handle_sys_enter_memfd_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_vhangup")
int handle_sys_exit_vhangup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_vhangup")
int handle_sys_enter_vhangup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_close_range")
int handle_sys_exit_close_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_close_range")
int handle_sys_enter_close_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_close")
int handle_sys_exit_close(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_close")
int handle_sys_enter_close(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_creat")
int handle_sys_exit_creat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_creat")
int handle_sys_enter_creat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_openat2")
int handle_sys_exit_openat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_openat2")
int handle_sys_enter_openat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_openat")
int handle_sys_exit_openat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_openat")
int handle_sys_enter_openat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_open")
int handle_sys_exit_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_open")
int handle_sys_enter_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fchown")
int handle_sys_exit_fchown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fchown")
int handle_sys_enter_fchown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_lchown")
int handle_sys_exit_lchown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_lchown")
int handle_sys_enter_lchown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_chown")
int handle_sys_exit_chown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_chown")
int handle_sys_enter_chown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fchownat")
int handle_sys_exit_fchownat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fchownat")
int handle_sys_enter_fchownat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_chmod")
int handle_sys_exit_chmod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_chmod")
int handle_sys_enter_chmod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fchmodat")
int handle_sys_exit_fchmodat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fchmodat")
int handle_sys_enter_fchmodat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fchmod")
int handle_sys_exit_fchmod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fchmod")
int handle_sys_enter_fchmod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_chroot")
int handle_sys_exit_chroot(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_chroot")
int handle_sys_enter_chroot(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fchdir")
int handle_sys_exit_fchdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fchdir")
int handle_sys_enter_fchdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_chdir")
int handle_sys_exit_chdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_chdir")
int handle_sys_enter_chdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_access")
int handle_sys_exit_access(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_access")
int handle_sys_enter_access(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_faccessat2")
int handle_sys_exit_faccessat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_faccessat2")
int handle_sys_enter_faccessat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_faccessat")
int handle_sys_exit_faccessat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_faccessat")
int handle_sys_enter_faccessat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fallocate")
int handle_sys_exit_fallocate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fallocate")
int handle_sys_enter_fallocate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ftruncate")
int handle_sys_exit_ftruncate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ftruncate")
int handle_sys_enter_ftruncate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_truncate")
int handle_sys_exit_truncate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_truncate")
int handle_sys_enter_truncate(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_copy_file_range")
int handle_sys_exit_copy_file_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_copy_file_range")
int handle_sys_enter_copy_file_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sendfile64")
int handle_sys_exit_sendfile64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sendfile64")
int handle_sys_enter_sendfile64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pwritev2")
int handle_sys_exit_pwritev2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pwritev2")
int handle_sys_enter_pwritev2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pwritev")
int handle_sys_exit_pwritev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pwritev")
int handle_sys_enter_pwritev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_preadv2")
int handle_sys_exit_preadv2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_preadv2")
int handle_sys_enter_preadv2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_preadv")
int handle_sys_exit_preadv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_preadv")
int handle_sys_enter_preadv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_writev")
int handle_sys_exit_writev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_writev")
int handle_sys_enter_writev(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_readv")
int handle_sys_exit_readv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_readv")
int handle_sys_enter_readv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pwrite64")
int handle_sys_exit_pwrite64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pwrite64")
int handle_sys_enter_pwrite64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pread64")
int handle_sys_exit_pread64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pread64")
int handle_sys_enter_pread64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_write")
int handle_sys_exit_write(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_write")
int handle_sys_enter_write(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_read")
int handle_sys_exit_read(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_read")
int handle_sys_enter_read(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_lseek")
int handle_sys_exit_lseek(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_lseek")
int handle_sys_enter_lseek(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_statx")
int handle_sys_exit_statx(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_statx")
int handle_sys_enter_statx(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_readlink")
int handle_sys_exit_readlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_readlink")
int handle_sys_enter_readlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_readlinkat")
int handle_sys_exit_readlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_readlinkat")
int handle_sys_enter_readlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_newfstat")
int handle_sys_exit_newfstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_newfstat")
int handle_sys_enter_newfstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_newfstatat")
int handle_sys_exit_newfstatat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_newfstatat")
int handle_sys_enter_newfstatat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_newlstat")
int handle_sys_exit_newlstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_newlstat")
int handle_sys_enter_newlstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_newstat")
int handle_sys_exit_newstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_newstat")
int handle_sys_enter_newstat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_execveat")
int handle_sys_exit_execveat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_execve")
int handle_sys_exit_execve(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pipe")
int handle_sys_exit_pipe(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pipe")
int handle_sys_enter_pipe(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pipe2")
int handle_sys_exit_pipe2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pipe2")
int handle_sys_enter_pipe2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rename")
int handle_sys_exit_rename(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rename")
int handle_sys_enter_rename(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_renameat")
int handle_sys_exit_renameat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_renameat")
int handle_sys_enter_renameat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_renameat2")
int handle_sys_exit_renameat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_link")
int handle_sys_exit_link(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_link")
int handle_sys_enter_link(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_linkat")
int handle_sys_exit_linkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_linkat")
int handle_sys_enter_linkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_symlink")
int handle_sys_exit_symlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_symlink")
int handle_sys_enter_symlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_symlinkat")
int handle_sys_exit_symlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_symlinkat")
int handle_sys_enter_symlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_unlink")
int handle_sys_exit_unlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_unlink")
int handle_sys_enter_unlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_unlinkat")
int handle_sys_exit_unlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_unlinkat")
int handle_sys_enter_unlinkat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_rmdir")
int handle_sys_exit_rmdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_rmdir")
int handle_sys_enter_rmdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mkdir")
int handle_sys_exit_mkdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mkdir")
int handle_sys_enter_mkdir(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mkdirat")
int handle_sys_exit_mkdirat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mkdirat")
int handle_sys_enter_mkdirat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mknod")
int handle_sys_exit_mknod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mknod")
int handle_sys_enter_mknod(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mknodat")
int handle_sys_exit_mknodat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mknodat")
int handle_sys_enter_mknodat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fcntl")
int handle_sys_exit_fcntl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fcntl")
int handle_sys_enter_fcntl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ioctl")
int handle_sys_exit_ioctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ioctl")
int handle_sys_enter_ioctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getdents64")
int handle_sys_exit_getdents64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getdents64")
int handle_sys_enter_getdents64(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getdents")
int handle_sys_exit_getdents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getdents")
int handle_sys_enter_getdents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ppoll")
int handle_sys_exit_ppoll(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ppoll")
int handle_sys_enter_ppoll(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_poll")
int handle_sys_exit_poll(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_poll")
int handle_sys_enter_poll(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pselect6")
int handle_sys_exit_pselect6(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pselect6")
int handle_sys_enter_pselect6(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_select")
int handle_sys_exit_select(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_select")
int handle_sys_enter_select(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_dup")
int handle_sys_exit_dup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_dup")
int handle_sys_enter_dup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_dup2")
int handle_sys_exit_dup2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_dup2")
int handle_sys_enter_dup2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_dup3")
int handle_sys_exit_dup3(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_dup3")
int handle_sys_enter_dup3(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sysfs")
int handle_sys_exit_sysfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sysfs")
int handle_sys_enter_sysfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mount_setattr")
int handle_sys_exit_mount_setattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mount_setattr")
int handle_sys_enter_mount_setattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_pivot_root")
int handle_sys_exit_pivot_root(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_pivot_root")
int handle_sys_enter_pivot_root(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_move_mount")
int handle_sys_exit_move_mount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_move_mount")
int handle_sys_enter_move_mount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fsmount")
int handle_sys_exit_fsmount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fsmount")
int handle_sys_enter_fsmount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mount")
int handle_sys_exit_mount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mount")
int handle_sys_enter_mount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_open_tree")
int handle_sys_exit_open_tree(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_open_tree")
int handle_sys_enter_open_tree(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_umount")
int handle_sys_exit_umount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_umount")
int handle_sys_enter_umount(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fremovexattr")
int handle_sys_exit_fremovexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fremovexattr")
int handle_sys_enter_fremovexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_lremovexattr")
int handle_sys_exit_lremovexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_lremovexattr")
int handle_sys_enter_lremovexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_removexattr")
int handle_sys_exit_removexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_removexattr")
int handle_sys_enter_removexattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_flistxattr")
int handle_sys_exit_flistxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_flistxattr")
int handle_sys_enter_flistxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_llistxattr")
int handle_sys_exit_llistxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_llistxattr")
int handle_sys_enter_llistxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_listxattr")
int handle_sys_exit_listxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_listxattr")
int handle_sys_enter_listxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fgetxattr")
int handle_sys_exit_fgetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fgetxattr")
int handle_sys_enter_fgetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_lgetxattr")
int handle_sys_exit_lgetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_lgetxattr")
int handle_sys_enter_lgetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getxattr")
int handle_sys_exit_getxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getxattr")
int handle_sys_enter_getxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fsetxattr")
int handle_sys_exit_fsetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fsetxattr")
int handle_sys_enter_fsetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_lsetxattr")
int handle_sys_exit_lsetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_lsetxattr")
int handle_sys_enter_lsetxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setxattr")
int handle_sys_exit_setxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setxattr")
int handle_sys_enter_setxattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_tee")
int handle_sys_exit_tee(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_tee")
int handle_sys_enter_tee(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_splice")
int handle_sys_exit_splice(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_splice")
int handle_sys_enter_splice(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_vmsplice")
int handle_sys_exit_vmsplice(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_vmsplice")
int handle_sys_enter_vmsplice(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sync_file_range")
int handle_sys_exit_sync_file_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sync_file_range")
int handle_sys_enter_sync_file_range(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fdatasync")
int handle_sys_exit_fdatasync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fdatasync")
int handle_sys_enter_fdatasync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fsync")
int handle_sys_exit_fsync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fsync")
int handle_sys_enter_fsync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_syncfs")
int handle_sys_exit_syncfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_syncfs")
int handle_sys_enter_syncfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sync")
int handle_sys_exit_sync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sync")
int handle_sys_enter_sync(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_utime")
int handle_sys_exit_utime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_utime")
int handle_sys_enter_utime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_utimes")
int handle_sys_exit_utimes(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_utimes")
int handle_sys_enter_utimes(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_futimesat")
int handle_sys_exit_futimesat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_futimesat")
int handle_sys_enter_futimesat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_utimensat")
int handle_sys_exit_utimensat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_utimensat")
int handle_sys_enter_utimensat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getcwd")
int handle_sys_exit_getcwd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getcwd")
int handle_sys_enter_getcwd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ustat")
int handle_sys_exit_ustat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ustat")
int handle_sys_enter_ustat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fstatfs")
int handle_sys_exit_fstatfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fstatfs")
int handle_sys_enter_fstatfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_statfs")
int handle_sys_exit_statfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_statfs")
int handle_sys_enter_statfs(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fsconfig")
int handle_sys_exit_fsconfig(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fsconfig")
int handle_sys_enter_fsconfig(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fspick")
int handle_sys_exit_fspick(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fspick")
int handle_sys_enter_fspick(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_fsopen")
int handle_sys_exit_fsopen(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_fsopen")
int handle_sys_enter_fsopen(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_inotify_rm_watch")
int handle_sys_exit_inotify_rm_watch(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_inotify_rm_watch")
int handle_sys_enter_inotify_rm_watch(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_inotify_add_watch")
int handle_sys_exit_inotify_add_watch(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_inotify_add_watch")
int handle_sys_enter_inotify_add_watch(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_inotify_init")
int handle_sys_exit_inotify_init(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_inotify_init")
int handle_sys_enter_inotify_init(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_inotify_init1")
int handle_sys_exit_inotify_init1(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_inotify_init1")
int handle_sys_enter_inotify_init1(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_pwait2")
int handle_sys_exit_epoll_pwait2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_pwait2")
int handle_sys_enter_epoll_pwait2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_pwait")
int handle_sys_exit_epoll_pwait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_pwait")
int handle_sys_enter_epoll_pwait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_wait")
int handle_sys_exit_epoll_wait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_wait")
int handle_sys_enter_epoll_wait(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_ctl")
int handle_sys_exit_epoll_ctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_ctl")
int handle_sys_enter_epoll_ctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_create")
int handle_sys_exit_epoll_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_create")
int handle_sys_enter_epoll_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_epoll_create1")
int handle_sys_exit_epoll_create1(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_epoll_create1")
int handle_sys_enter_epoll_create1(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_signalfd")
int handle_sys_exit_signalfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_signalfd")
int handle_sys_enter_signalfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_signalfd4")
int handle_sys_exit_signalfd4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_signalfd4")
int handle_sys_enter_signalfd4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timerfd_gettime")
int handle_sys_exit_timerfd_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timerfd_gettime")
int handle_sys_enter_timerfd_gettime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timerfd_settime")
int handle_sys_exit_timerfd_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timerfd_settime")
int handle_sys_enter_timerfd_settime(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_timerfd_create")
int handle_sys_exit_timerfd_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_timerfd_create")
int handle_sys_enter_timerfd_create(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_eventfd")
int handle_sys_exit_eventfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_eventfd")
int handle_sys_enter_eventfd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_eventfd2")
int handle_sys_exit_eventfd2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_eventfd2")
int handle_sys_enter_eventfd2(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_pgetevents")
int handle_sys_exit_io_pgetevents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_pgetevents")
int handle_sys_enter_io_pgetevents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_getevents")
int handle_sys_exit_io_getevents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_getevents")
int handle_sys_enter_io_getevents(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_cancel")
int handle_sys_exit_io_cancel(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_cancel")
int handle_sys_enter_io_cancel(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_submit")
int handle_sys_exit_io_submit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_submit")
int handle_sys_enter_io_submit(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_destroy")
int handle_sys_exit_io_destroy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_destroy")
int handle_sys_enter_io_destroy(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_setup")
int handle_sys_exit_io_setup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_setup")
int handle_sys_enter_io_setup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_flock")
int handle_sys_exit_flock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_flock")
int handle_sys_enter_flock(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_open_by_handle_at")
int handle_sys_exit_open_by_handle_at(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_open_by_handle_at")
int handle_sys_enter_open_by_handle_at(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_name_to_handle_at")
int handle_sys_exit_name_to_handle_at(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_name_to_handle_at")
int handle_sys_enter_name_to_handle_at(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_quotactl_fd")
int handle_sys_exit_quotactl_fd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_quotactl_fd")
int handle_sys_enter_quotactl_fd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_quotactl")
int handle_sys_exit_quotactl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_quotactl")
int handle_sys_enter_quotactl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_msgrcv")
int handle_sys_exit_msgrcv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_msgrcv")
int handle_sys_enter_msgrcv(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_msgsnd")
int handle_sys_exit_msgsnd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_msgsnd")
int handle_sys_enter_msgsnd(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_msgctl")
int handle_sys_exit_msgctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_msgctl")
int handle_sys_enter_msgctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_msgget")
int handle_sys_exit_msgget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_msgget")
int handle_sys_enter_msgget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_semop")
int handle_sys_exit_semop(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_semop")
int handle_sys_enter_semop(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_semtimedop")
int handle_sys_exit_semtimedop(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_semtimedop")
int handle_sys_enter_semtimedop(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_semctl")
int handle_sys_exit_semctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_semctl")
int handle_sys_enter_semctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_semget")
int handle_sys_exit_semget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_semget")
int handle_sys_enter_semget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_shmdt")
int handle_sys_exit_shmdt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_shmdt")
int handle_sys_enter_shmdt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_shmat")
int handle_sys_exit_shmat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_shmat")
int handle_sys_enter_shmat(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_shmctl")
int handle_sys_exit_shmctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_shmctl")
int handle_sys_enter_shmctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_shmget")
int handle_sys_exit_shmget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_shmget")
int handle_sys_enter_shmget(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_getsetattr")
int handle_sys_exit_mq_getsetattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_getsetattr")
int handle_sys_enter_mq_getsetattr(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_notify")
int handle_sys_exit_mq_notify(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_notify")
int handle_sys_enter_mq_notify(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_timedreceive")
int handle_sys_exit_mq_timedreceive(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_timedreceive")
int handle_sys_enter_mq_timedreceive(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_timedsend")
int handle_sys_exit_mq_timedsend(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_timedsend")
int handle_sys_enter_mq_timedsend(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_unlink")
int handle_sys_exit_mq_unlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_unlink")
int handle_sys_enter_mq_unlink(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_mq_open")
int handle_sys_exit_mq_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_mq_open")
int handle_sys_enter_mq_open(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_keyctl")
int handle_sys_exit_keyctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_keyctl")
int handle_sys_enter_keyctl(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_request_key")
int handle_sys_exit_request_key(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_request_key")
int handle_sys_enter_request_key(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_add_key")
int handle_sys_exit_add_key(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_add_key")
int handle_sys_enter_add_key(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ioprio_get")
int handle_sys_exit_ioprio_get(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ioprio_get")
int handle_sys_enter_ioprio_get(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_ioprio_set")
int handle_sys_exit_ioprio_set(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_ioprio_set")
int handle_sys_enter_ioprio_set(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_uring_register")
int handle_sys_exit_io_uring_register(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_uring_register")
int handle_sys_enter_io_uring_register(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_uring_setup")
int handle_sys_exit_io_uring_setup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_uring_setup")
int handle_sys_enter_io_uring_setup(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_io_uring_enter")
int handle_sys_exit_io_uring_enter(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_io_uring_enter")
int handle_sys_enter_io_uring_enter(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getrandom")
int handle_sys_exit_getrandom(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getrandom")
int handle_sys_enter_getrandom(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_recvmmsg")
int handle_sys_exit_recvmmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_recvmmsg")
int handle_sys_enter_recvmmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_recvmsg")
int handle_sys_exit_recvmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_recvmsg")
int handle_sys_enter_recvmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sendmmsg")
int handle_sys_exit_sendmmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sendmmsg")
int handle_sys_enter_sendmmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sendmsg")
int handle_sys_exit_sendmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sendmsg")
int handle_sys_enter_sendmsg(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_shutdown")
int handle_sys_exit_shutdown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_shutdown")
int handle_sys_enter_shutdown(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getsockopt")
int handle_sys_exit_getsockopt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getsockopt")
int handle_sys_enter_getsockopt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_setsockopt")
int handle_sys_exit_setsockopt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_setsockopt")
int handle_sys_enter_setsockopt(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_recvfrom")
int handle_sys_exit_recvfrom(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_recvfrom")
int handle_sys_enter_recvfrom(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_sendto")
int handle_sys_exit_sendto(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_sendto")
int handle_sys_enter_sendto(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getpeername")
int handle_sys_exit_getpeername(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getpeername")
int handle_sys_enter_getpeername(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_getsockname")
int handle_sys_exit_getsockname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_getsockname")
int handle_sys_enter_getsockname(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_connect")
int handle_sys_exit_connect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_connect")
int handle_sys_enter_connect(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_accept")
int handle_sys_exit_accept(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_accept")
int handle_sys_enter_accept(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_accept4")
int handle_sys_exit_accept4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_accept4")
int handle_sys_enter_accept4(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_listen")
int handle_sys_exit_listen(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_listen")
int handle_sys_enter_listen(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_bind")
int handle_sys_exit_bind(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_bind")
int handle_sys_enter_bind(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_socketpair")
int handle_sys_exit_socketpair(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_socketpair")
int handle_sys_enter_socketpair(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_exit_socket")
int handle_sys_exit_socket(void *ctx)
{
	return 0;
}
SEC("tp/syscalls/sys_enter_socket")
int handle_sys_enter_socket(void *ctx)
{
	return 0;
}
