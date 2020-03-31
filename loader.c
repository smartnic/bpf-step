#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	char filename[256];
	FILE *f;
	int i, sock;

  /* Usage: <binary> kern_dot_o_file bpf_prog_name */
  if (argc < 2) {
    printf("Usage: %s kern_dot_o_file bpf_prog_name\n", argv[0]);
    return 1;
  }

	snprintf(filename, sizeof(filename), "%s", argv[1]);

  struct bpf_insn * prog;
  int prog_len;
  
  if (get_prog(filename, argv[2], strlen(argv[2]),
               &prog_len, &prog)) {
    printf("Failed to extract a program from the provided .o filename %s"
           " and BPF program name %s\n", argv[1], argv[2]);
    return 1;
  }

  printf("Got program with a length %d \n", prog_len);

  return 0;
}

