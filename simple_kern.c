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
//   int one = 1; 

	long *value;


   int time1 = bpf_ktime_get_ns();

	value = bpf_map_lookup_elem(&my_map, &zero);

	if (value)
		*value = time1;
//   bpf_map_update_elem(&my_map, &zero, &time1, BPF_ANY);
/*
   int time2 = bpf_ktime_get_ns(); 
   bpf_map_update_elem(&my_map, &one, &time2, BPF_ANY);*/
   return 0;
}
char _license[] SEC("license") = "GPL";
