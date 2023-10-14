# MOAT: Towards Safe BPF Kernel Extension

This is the open-source repo for the paper titled "MOAT: Towards Safe BPF Kernel
Extension".

## Directories

- `moat_linux`: Our modified Linux kernel with MOAT-support, based on Linux 6.1.38
- `libbpf-bootstrap`: The user space facilities for convenient loading &
executing BPF programs
- `libbpf-bootstrap/examples/moat_test`: Our test cases used in the paper

## Preparation

### Kernel Installation

```bash
sudo make && sudo make modules_install
```

### Test-case Compile

Please follow the
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/) to get
necessary tools ready.

```bash
cd libbpf-bootstrap/examples/moat_test/
make
```

## Experiment Notes
> Note that the performance of MOAT could vary depending on your hardware
> setup.
## Network Experiment

> You need at least two machines for the network experiment; one is the
> host generating traffic and the other is the tested device with MOAT-hardened
> BPF programs.

1. Install the kernel with MOAT-support on the tested device.
2. Ensure that two machines are in the same network.
3. Compile the test cases, such as `sockex{1...4}`.
4. On the tested device, run `iperf3 -s` to process packets.
5. On the host, run `iperf3` to generate packets.

## System Tracing Experiment

1. Compile the test case, `tracepoints.c`. It loads 11 BPF programs to trace
system events like page faults.
2. Compile the [UnixBench](https://github.com/kdlucas/byte-unixbench).
3. Load the BPF programs by `./tracepoints`.
4. Run the UnixBench with `./Run -c $(nproc) > results`.

## `seccomp-BPF` Experiment

Please follow the guide in [sysfilter](https://gitlab.com/Egalito/sysfilter)
to use `sysfilter` to harden Nginx, then run `wrk` to benchmark the hardened
Nginx.

## MOAT's Cost vs. #BPF Programs

In the paper, we also include two experiments showing that MOAT supports
numerous BPF programs.

To reproduce the first experiment, you can find there are
`execve_X.c` and `execve_X.bpf.c` sources in `moat_test` folder. These
programs attach `X` BPF programs to the `exec` system call. You can then
run `./unix_syscall <duration> e` to obtain the throughput of `execl`.

To reproduce the second experiment, you can find there is a `syscalls.c`
and `syscalls.bpf.c` sources in `moat_test` folder. These programs attach
*all* available system call tracepoints in the system. You can then run
UnixBench to obtain an overall system performance score.

> Depending on your configuration, the tracepoints available in our
> system may not be completely the same as yours; in such case,
> please regenerate the `syscall.bpf.c` with `syscall2bpf.py`

## Other tools

- [UnixBench](https://github.com/kdlucas/byte-unixbench)
- [wrk: Modern HTTP benchmarking tool](https://github.com/wg/wrk)
- [Nginx](https://github.com/nginx/nginx)
- [sysfilter](https://gitlab.com/Egalito/sysfilter)
