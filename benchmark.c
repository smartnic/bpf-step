#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "libbpf.h"
static int benchmark(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;
	FILE *f;

    
	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 2);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	struct bpf_insn prog[] = {


		BPF_MOV64_IMM(BPF_REG_1, 0), /* r0 = 0 */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4), /* *(u32 *)(fp - 4) = r0 */
        BPF_MOV64_IMM(BPF_REG_1, 1),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ktime_get_ns),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
		BPF_MOV64_IMM(BPF_REG_1, 0), /* r0 = 0 */
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0), /* *(u32 *)(fp - 4) = r0 */



        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ktime_get_ns),
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),

		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),

		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),

		BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0), /* *(u32 *)(fp - 4) = r0 */


		BPF_MOV64_IMM(BPF_REG_0, 0), 
		BPF_EXIT_INSN(),

	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				"GPL", 0);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}


	// Attempt to print the bpf_log_buf for verifier information
	printf("Log buffer:\n %s\n---\n", bpf_log_buf);
	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			  sizeof(prog_fd)) == 0);

	f = popen("ping -c1 localhost", "r");
	(void) f;
     
    printf("************ PROGRAM SUCCESSFULLY LOADED **************\n");
    sleep(1);


    int key_0 = 0;
    int key_1 = 1;
    unsigned long time_begin, time_end, time_begin_ms, time_end_ms;

    int ret_code_0 = bpf_lookup_elem(map_fd, &key_0, &time_begin);
    int ret_code_1 = bpf_lookup_elem(map_fd, &key_1, &time_end);
   
    int NS_IN_MS = 1000000;  
    if (ret_code_0 == 0) {
        time_begin_ms = (time_begin / NS_IN_MS);
        printf("time begin ms %lu\n", time_begin_ms);

        printf("time begin    %lu\n", time_begin);
    }
    if (ret_code_1 == 0) {

        time_end_ms = (time_end / NS_IN_MS);
        printf("time end ms %lu\n", time_end_ms);
        printf("time end    %lu\n", time_end);
    }
    if (ret_code_0 == 0 && ret_code_1 == 0) {

        unsigned long time_elapsed = time_end - time_begin;
        unsigned long time_elapsed_ms = time_end_ms - time_begin_ms;

        printf("time elapsed ms %lu\n", time_elapsed_ms);
        printf("time elapsed    %lu\n", time_elapsed);
    } 

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{

	return benchmark();
}
