#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include "bpf_helpers.h"
#include <unistd.h>
#include <arpa/inet.h>


int main (int argc, char ** argv)
{

	char filename[256];
	FILE *f;
	int i, sock;

  snprintf(filename, sizeof(filename), "%s", "sockex1_kern.o");
  // Look at SEC of original .c file to find progname
  char * progname = "socket1"; 
  struct bpf_insn * prog = '\0';
  struct bpf_map_def * maps = '\0';
  int prog_len;
  int map_len;

  if (get_prog_and_data(filename, progname, strlen(progname),
               &prog_len, &prog, &map_len, &maps)) {
    printf("Failed to extract a program from the provided .o filename %s"
           " and BPF program name %s\n", argv[1], argv[2]);
    return 1;
  }
    printf("Got program with a length %d \n", prog_len);

    if (prog == '\0') {
        printf("prog is null\n");
        return 1;
    }
    if (maps == '\0') {
        printf("maps is null\n");
    }
    else {
        printf("Map length: %d\n", map_len);
        interpret_bpf_map_defs(&maps, map_len);
    }
    interpret_bpf_insns(&prog, prog_len);
    return 0;
}

void interpret_bpf_map_defs(struct bpf_map_def ** maps, int map_len) 
{
    int i;
    printf("Map data:\n");
	for (i = 0; i < map_len / sizeof(struct bpf_map_def); i++) {
        struct bpf_map_def map = (*maps)[i];
        printf("Type: %u, key_size: %u, value_size: %u, max_entries: %u\n", map.type, map.key_size, map.value_size, map.max_entries); 
	}
}
void interpret_bpf_insns(struct bpf_insn ** prog, int prog_len) 
{
    char * mnemonic = (char *)(malloc(sizeof(char)*10)); 
    int i;
    printf("eBPF instructions:\n");
    for (i = 0; i < prog_len / sizeof(struct bpf_insn); ++i) {
        struct bpf_insn insn = (*prog)[i];
        printf("insn: %u %u %u %d %d\t", insn.code, insn.dst_reg, insn.src_reg, insn.off, insn.imm);
        determine_mnemonic(insn.code, mnemonic);
        printf("Mnemonic: %s\n", mnemonic);
    }

    free(mnemonic);
 
}
void determine_mnemonic(__u8 opcode, char * mnemonic) 
{

    if (opcode == 0x07)  strcpy(mnemonic, "add"); 
    else if (opcode == 0x0f)  strcpy(mnemonic, "add"); 
    else if (opcode == 0x17)  strcpy(mnemonic, "sub"); 
    else if (opcode == 0x1f)  strcpy(mnemonic, "sub"); 
    else if (opcode == 0x27)  strcpy(mnemonic, "mul"); 
    else if (opcode == 0x1f)  strcpy(mnemonic, "mul"); 
    else if (opcode == 0x37)  strcpy(mnemonic, "div"); 
    else if (opcode == 0x3f)  strcpy(mnemonic, "div"); 
    else if (opcode == 0x47)  strcpy(mnemonic, "or"); 
    else if (opcode == 0x4f)  strcpy(mnemonic, "or"); 
    else if (opcode == 0x57)  strcpy(mnemonic, "and"); 
    else if (opcode == 0x5f)  strcpy(mnemonic, "and"); 
    else if (opcode == 0x67)  strcpy(mnemonic, "lsh"); 
    else if (opcode == 0x6f)  strcpy(mnemonic, "lsh"); 
    else if (opcode == 0x77)  strcpy(mnemonic, "rsh"); 
    else if (opcode == 0x7f)  strcpy(mnemonic, "rsh"); 
    else if (opcode == 0x87)  strcpy(mnemonic, "neg"); 
    else if (opcode == 0x8f)  strcpy(mnemonic, "mod"); 
    else if (opcode == 0x97)  strcpy(mnemonic, "xor"); 
    else if (opcode == 0x9f)  strcpy(mnemonic, "xor"); 
    else if (opcode == 0xa7)  strcpy(mnemonic, "mov"); 
    else if (opcode == 0xaf)  strcpy(mnemonic, "mov"); 
    else if (opcode == 0xb7)  strcpy(mnemonic, "arsh"); 
    else if (opcode == 0xbf)  strcpy(mnemonic, "arsh"); 
    else if (opcode == 0xd4)  strcpy(mnemonic, "le64"); 
    else if (opcode == 0xdc)  strcpy(mnemonic, "be64"); 
    else if (opcode == 0x18)  strcpy(mnemonic, "lddw"); 
    else if (opcode == 0x20)  strcpy(mnemonic, "ldabsw"); 
    else if (opcode == 0x28)  strcpy(mnemonic, "ldabsh"); 
    else if (opcode == 0x30)  strcpy(mnemonic, "ldabsb"); 
    else if (opcode == 0x38)  strcpy(mnemonic, "ldabsdw"); 
    else if (opcode == 0x40)  strcpy(mnemonic, "ldindw"); 
    else if (opcode == 0x48)  strcpy(mnemonic, "ldindh"); 
    else if (opcode == 0x50)  strcpy(mnemonic, "ldindb"); 
    else if (opcode == 0x58)  strcpy(mnemonic, "ldinddw"); 

    else if (opcode == 0x61)  strcpy(mnemonic, "ldxw"); 
    else if (opcode == 0x69)  strcpy(mnemonic, "ldxh"); 
    else if (opcode == 0x71)  strcpy(mnemonic, "ldsb"); 
    else if (opcode == 0x79)  strcpy(mnemonic, "ldxdw"); 
    else if (opcode == 0x62)  strcpy(mnemonic, "stw"); 
    else if (opcode == 0x6a)  strcpy(mnemonic, "sth"); 
    else if (opcode == 0x72)  strcpy(mnemonic, "stb"); 
    else if (opcode == 0x7a)  strcpy(mnemonic, "stdw"); 
    else if (opcode == 0x63)  strcpy(mnemonic, "stxw"); 
    else if (opcode == 0x6b)  strcpy(mnemonic, "stxh"); 
    else if (opcode == 0x73)  strcpy(mnemonic, "stxb"); 
    else if (opcode == 0x7b)  strcpy(mnemonic, "stxdw"); 

    else if (opcode == 0x05)  strcpy(mnemonic, "ja"); 
    else if (opcode == 0x15)  strcpy(mnemonic, "jeq"); 
    else if (opcode == 0x1d)  strcpy(mnemonic, "jeq"); 
    else if (opcode == 0x25)  strcpy(mnemonic, "jgt"); 
    else if (opcode == 0x2d)  strcpy(mnemonic, "jgt"); 
    else if (opcode == 0x35)  strcpy(mnemonic, "jge"); 
    else if (opcode == 0x3d)  strcpy(mnemonic, "jge"); 
    else if (opcode == 0xa5)  strcpy(mnemonic, "jit"); 
    else if (opcode == 0xad)  strcpy(mnemonic, "jit"); 
    else if (opcode == 0xb5)  strcpy(mnemonic, "jle"); 
    else if (opcode == 0xbd)  strcpy(mnemonic, "jle"); 
    else if (opcode == 0x45)  strcpy(mnemonic, "jset"); 

    else if (opcode == 0x4d)  strcpy(mnemonic, "jet"); 
    else if (opcode == 0x55)  strcpy(mnemonic, "jne"); 
    else if (opcode == 0x5d)  strcpy(mnemonic, "jne"); 
    else if (opcode == 0x65)  strcpy(mnemonic, "jsgt"); 
    else if (opcode == 0x6d)  strcpy(mnemonic, "jsgt"); 
    else if (opcode == 0x75)  strcpy(mnemonic, "jsge"); 
    else if (opcode == 0x7d)  strcpy(mnemonic, "jsgt"); 
    else if (opcode == 0xc5)  strcpy(mnemonic, "jslt"); 
    else if (opcode == 0xcd)  strcpy(mnemonic, "jslt"); 
    else if (opcode == 0xd5)  strcpy(mnemonic, "jsle"); 
    else if (opcode == 0xdd)  strcpy(mnemonic, "jsle"); 
    else if (opcode == 0x85)  strcpy(mnemonic, "call"); 
    else if (opcode == 0x95)  strcpy(mnemonic, "exit"); 
    else  strcpy(mnemonic, "nop");
    
}