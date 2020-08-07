CC=gcc
BPFCC=clang
BPFLLC=llc

cprogs = sock_example get-rekt-hardened benchmark 
bpfprogs = sockex1 elf_parse

all: $(cprogs) $(bpfprogs)
	bash perm.sh

%.o: %.c
	$(CC) -c $< -o $@

sock_example: sock_example.o libbpf.o
	$(CC) $^ -o $@

benchmark: benchmark.o libbpf.o
	$(CC) $^ -o $@

sockex1: sockex1_user.o sockex1_kern.o bpf_load.o libbpf.o 
	$(CC) sockex1_user.o bpf_load.o libbpf.o -lelf -o $@

time: time_user.o time_kern.o bpf_load.o libbpf.o 
	$(CC) time_user.o bpf_load.o libbpf.o -lelf -o $@

elf_parse: elf_parse.o bpf_load.o libbpf.o 
	$(CC) elf_parse.o bpf_load.o libbpf.o -lelf -o $@

sockex1_kern.o: sockex1_kern.c
	$(BPFCC) -O2 -emit-llvm -c $< -o -| $(BPFLLC) -march=bpf -filetype=obj -o $@
	$(BPFCC) -O2 -emit-llvm -c $< -o -| $(BPFLLC) -march=bpf -filetype=asm -o $@.s

time_kern.o: time_kern.c
	$(BPFCC)  -O1 -emit-llvm -c $< -o -| $(BPFLLC) -march=bpf -filetype=obj -o $@
	$(BPFCC)  -O1 -emit-llvm -c $< -o -| $(BPFLLC) -march=bpf -filetype=asm -o $@.s


loader: loader.o bpf_load.o libbpf.o
	$(CC) loader.o bpf_load.o libbpf.o -lelf -o $@

clean:
	rm -f *.o *.o.s
	rm -f $(cprogs) $(bpfprogs)
