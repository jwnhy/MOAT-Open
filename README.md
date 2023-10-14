# MOAT: Towards Safe BPF Kernel Extension

This is the open-source repo for paper titled
"MOAT: Towards Safe BPF Kernel Extension"

## Directories

- `moat_linux`: Our modified Linux kernel with MOAT-support, based on Linux 6.1.38
- `libbpf-bootstrap`: The user space facilities for conveniently loading &
executing BPF programs
- `libbpf-bootstrap/examples/moat_test`: Our test cases used in the paper

## Other used tools

- [UnixBench](https://github.com/kdlucas/byte-unixbench)
- [wrk: Modern HTTP benchmarking tool](https://github.com/wg/wrk)
- [Nginx](https://github.com/nginx/nginx)
- [sysfilter](https://gitlab.com/Egalito/sysfilter)
