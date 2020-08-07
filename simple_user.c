#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <unistd.h>
#include <arpa/inet.h>
int main(int ac, char **argv)
{
	char filename[256];
	FILE *f;
	int i, sock;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
        printf("Failed to load\n");
		printf("%s", bpf_log_buf);
		return 1;
	}

	// Print the BPF verifier log anyway
	printf("%s", bpf_log_buf);

    int key_0 = 0;
    int key_1 = 1;
    unsigned long time_begin, time_end, time_begin_ms, time_end_ms;
	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd,
			  sizeof(prog_fd[0])) == 0);

	f = popen("ping -c1 localhost", "r");
	(void) f;

    printf("************ PROGRAM SUCCESSFULLY LOADED **************\n");

    sleep(1);
    int ret_code_0 = bpf_lookup_elem(map_fd[0], &key_0, &time_begin);
    int ret_code_1 = bpf_lookup_elem(map_fd[0], &key_1, &time_end);
   
    int NS_IN_MS = 1000000;  
    if (ret_code_0 == 0) {
        time_begin_ms = (time_begin / NS_IN_MS);
        printf("time begin %lu\n", time_begin_ms);
    }
    if (ret_code_1 == 0) {

        time_end_ms = (time_end / NS_IN_MS);
        printf("time end ms %lu\n", time_end_ms);
        
        printf("time end    %lu\n", time_end);
    }
    if (ret_code_0 == 0 && ret_code_1 == 0) {

        unsigned long time_elapsed = time_end_ms - time_begin_ms;
        printf("time elapsed %lu\n", time_elapsed);
    } 

	return 0;
}

