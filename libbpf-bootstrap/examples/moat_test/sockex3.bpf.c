#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");

/* 
 * Count packet sizes passing through this interface */
SEC("socket")
int sockex3(struct __sk_buff *skb)
{
	  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    int size = ETH_HLEN + sizeof(struct iphdr);
    switch (proto) {
        case IPPROTO_TCP: size += sizeof(struct tcphdr); break;
        case IPPROTO_UDP: size += sizeof(struct udphdr); break;
        default: size = 0; break;                               // drop this packet
    }
    return size;
}
char _license[] SEC("license") = "GPL";
