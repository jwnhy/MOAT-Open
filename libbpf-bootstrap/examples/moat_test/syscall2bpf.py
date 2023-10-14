import os

file = open('./syscalls', 'r')
print(r'#include <linux/bpf.h>')
print(r'#include <bpf/bpf_helpers.h>')
print(r'char LICENSE[] SEC("license") = "Dual BSD/GPL";')
    
for line in file.readlines():
    if not line.startswith('syscalls:'):
        continue
    tp_name = line[line.find(':')+1:]
    print(f'SEC("tp/syscalls/{tp_name.strip()}")')
    print(f'int handle_{tp_name}(void *ctx)')
    print('{ return 0; }')
