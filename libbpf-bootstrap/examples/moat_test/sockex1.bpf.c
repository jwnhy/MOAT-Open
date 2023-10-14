#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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
int sockex1(struct __sk_buff *skb)
{
	long *value;
  int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}
char _license[] SEC("license") = "GPL";
