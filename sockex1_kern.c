#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
        int index = load_byte(skb, ETH_HLEN + 9);
	long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}
char _license[] SEC("license") = "GPL";
