// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "dropfilter.skel.h"

static struct env {
	const char *interface;
	int cnt;
} env;
static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct dropfilter_bpf *skel;
	int err, prog_fd, sock;

	env.interface = "lo";
  env.cnt = atoi(argv[1]);

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = dropfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	for (int i = 0; i < env.cnt; i++) {
    printf("adding %d\n", i);
		sock = open_raw_sock(env.interface);
		if (sock < 0) {
			err = -2;
			fprintf(stderr, "Failed to open raw socket\n");
			goto cleanup;
		}

		/* Attach BPF program to raw socket */
		prog_fd = bpf_program__fd(skel->progs.dropfilter);
		if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
			err = -3;
			fprintf(stderr, "Failed to attach to raw socket\n");
			goto cleanup;
		}
	}
	/* Process events */
	while (!exiting) {
		sleep(1);
	}

cleanup:
	dropfilter_bpf__destroy(skel);
	return -err;
}
