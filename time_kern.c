#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 2,
};


SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    int zero = 0;
    int one = 1; 

    unsigned long *value1;
    unsigned long *value2;
    unsigned long time1 = bpf_ktime_get_ns();

	value1 = bpf_map_lookup_elem(&my_map, &zero);
	if (value1)
		*value1 = time1;
      unsigned long time2 = bpf_ktime_get_ns(); 
	value2 = bpf_map_lookup_elem(&my_map, &one);
	if (value2)
		*value2 = time2;

   return 0;
}
char _license[] SEC("license") = "GPL";
