

import jinja2
env = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(''))
t = env.get_template("benchmark_to_run.j2")
prog = t.render(
    setup = 'BPF_MOV64_IMM(BPF_REG_8, 0),',
    num_insns = 600,
    insn = 'BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1),',
)
f = open('benchmark.c', 'wt', encoding='utf-8')
f.write(prog)


