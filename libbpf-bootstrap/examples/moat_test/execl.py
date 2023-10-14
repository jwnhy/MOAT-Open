import os
import sys
cnt = int(sys.argv[1]) * 2
sys.stdout = open(f'execve_{cnt}.bpf.c', 'w') 

print(r'#include <linux/bpf.h>')
print(r'#include <bpf/bpf_helpers.h>')
print(r'char LICENSE[] SEC("license") = "Dual BSD/GPL";')
for i in range(0, int(sys.argv[1])):
    tp_name = 'sys_enter_execve'
    print(f'SEC("tp/syscalls/{tp_name.strip()}")')
    print(f'int handle_{tp_name}{i}(void *ctx)')
    print('{ return 0; }')

    tp_name = 'sys_exit_execve'
    print(f'SEC("tp/syscalls/{tp_name.strip()}")')
    print(f'int handle_{tp_name}{i}(void *ctx)')
    print('{ return 0; }')
