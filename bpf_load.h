#ifndef __BPF_LOAD_H
#define __BPF_LOAD_H

#define MAX_MAPS 32
#define MAX_PROGS 32

#include <gelf.h>
#include "bpf_helpers.h"
extern int map_fd[MAX_MAPS];
extern int prog_fd[MAX_PROGS];
extern int event_fd[MAX_PROGS];

/* parses elf file compiled by llvm .c->.o
 * . parses 'maps' section and creates maps via BPF syscall
 * . parses 'license' section and passes it to syscall
 * . parses elf relocations for BPF maps and adjusts BPF_LD_IMM64 insns by
 *   storing map_fd into insn->imm and marking such insns as BPF_PSEUDO_MAP_FD
 * . loads eBPF programs via BPF syscall
 *
 * One ELF file can contain multiple BPF programs which will be loaded
 * and their FDs stored stored in prog_fd array
 *
 * returns zero on success
 */
int load_bpf_file(char *path);

/* parses elf file, and returns a bpf_insn* for the program name that
 * is requested. */
int get_prog(char *path, char *progname, int progname_len, int
             *prog_len, struct bpf_insn **prog);
int get_prog_and_data(char *path, char *progname,
             int progname_len, int *prog_len,
             struct bpf_insn** prog, int *map_len, 
             struct bpf_map_def** maps, Elf_Data ** symtab, uint64_t *num_entries);
 
void read_trace_pipe(void);

#endif
