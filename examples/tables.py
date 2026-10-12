"""sys_call_table, the IDT and MSR_LSTAR, each target placed.

    python examples/tables.py [vm]
"""

import sys

from rootview.rvtools import Modules, Tables, attach

with attach(sys.argv[1] if len(sys.argv) > 1 else None) as g:
    mods = Modules(g)
    texts = {i.name: (i.text_base, i.text_size) for i in map(mods.info, mods.module_list())}
    t = Tables(g, texts)
    with g.snapshot():
        syscalls, gates, frames, lstar = t.syscall_table(), t.idt(), t.idt_frames(), t.lstar()


def where(addr):
    p = t.place(addr)
    name = (f"{p.symbol}+{p.offset:#x}" if p.offset else p.symbol) if p.symbol else f"[{p.module}]" if p.module else "?"
    return f"{name:<44} {'text' if p.in_text else 'module' if p.module else 'outside'}"


print(f"== sys_call_table: {len(syscalls)} entries")
for nr, a in enumerate(syscalls):
    print(f"  {nr:>4} {a:#018x} {where(a)}")
print(f"== idt: {len(gates)} present gates; IDTR frame {frames[0]:#x}, idt_table frame {frames[1]:#x}")
for gate in gates:
    print(f"  {gate.vector:>4} {gate.handler:#018x} {where(gate.handler)} sel={gate.selector:#x} "
          f"type={gate.type:#x} dpl={gate.dpl} ist={gate.ist}")
print(f"== lstar: {lstar:#018x} {where(lstar)}")
