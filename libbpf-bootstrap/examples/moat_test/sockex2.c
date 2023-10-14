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
#include "sockex2.skel.h"

static struct env {
	const char *interface;
} env;

struct sockex2_bpf *skel;
const char argp_program_doc[] =
	"BPF socket filter demo application.\n"
	"\n"
	"This program watch network packet of specified interface and print out src/dst\n"
	"information.\n"
	"\n"
	"Currently only IPv4 is supported.\n"
	"\n"
	"USAGE: ./sockfilter [-i <interface>]\n";

static const struct argp_option opts[] = {
	{ "interface", 'i', "INTERFACE", 0, "Network interface to attach" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i':
		env.interface = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};


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
  int key;
  long long count;
  key = IPPROTO_TCP;
  bpf_map__lookup_elem(skel->maps.my_map, &key, sizeof(key), &count, sizeof(count), 0);
  printf("TCP: %lld\n", count);

  key = IPPROTO_UDP;
  bpf_map__lookup_elem(skel->maps.my_map, &key, sizeof(key), &count, sizeof(count), 0);
  printf("UDP: %lld\n", count);
	
	exiting = true;
}

int main(int argc, char **argv)
{
	int err, prog_fd, sock;

	env.interface = "lo";
	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return -err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = sockex2_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	sock = open_raw_sock(env.interface);
	if (sock < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	/* Attach BPF program to raw socket */
	prog_fd = bpf_program__fd(skel->progs.sockex2);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	/* Process events */
	while (!exiting) {
		sleep(1);
	}

cleanup:
	sockex2_bpf__destroy(skel);
	return -err;
}

