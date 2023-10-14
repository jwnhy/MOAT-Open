# MOAT: Towards Safe BPF Kernel Extension

This is the open-source repo for paper titled "MOAT: Towards Safe BPF Kernel
Extension"

## Directories

- `moat_linux`: Our modified Linux kernel with MOAT-support, based on Linux 6.1.38
- `libbpf-bootstrap`: The user space facilities for conveniently loading &
executing BPF programs
- `libbpf-bootstrap/examples/moat_test`: Our test cases used in the paper


## Kernel Installation

```bash
sudo make && sudo make modules_install
```

## Test-case Compile

Please follow the
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/) to get
necessary tools ready.

```bash
cd libbpf-bootstrap/examples/moat_test/
make
```

## Network Experiment

> Note that the performance of MOAT could vary depending on your hardware
> setup. You need at least two machines for the network experiment, one is the
> host generating traffic, the other is the tested device with MOAT-hardened
> BPF programs.


## Other tools

- [UnixBench](https://github.com/kdlucas/byte-unixbench)
- [wrk: Modern HTTP benchmarking tool](https://github.com/wg/wrk)
- [Nginx](https://github.com/nginx/nginx)
- [sysfilter](https://gitlab.com/Egalito/sysfilter)
