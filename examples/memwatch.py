"""Watch writes to sys_call_table and the IDT, decoded per slot.

    python examples/memwatch.py [vm] [seconds]
"""

import sys
import time

from rootview.rvtools import MemWatch, Symbols, Tables, attach

vm = sys.argv[1] if len(sys.argv) > 1 else None
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 30

with attach(vm) as g:
    syms = Symbols(g)
    t = Tables(g)
    with g.snapshot():
        sct, n = g.sym("sys_call_table"), len(t.syscall_table())
        idt = g.reg("idtr_base")
    watches = [MemWatch(g, "sct", sct, 8 * n, 8), MemWatch(g, "idt", idt, 256 * 16, 16)]
    for w in watches:
        w.start_watching()
    print(f"watching sys_call_table ({n} entries) and the IDT for {seconds:g}s")
    try:
        deadline = time.time() + seconds
        while time.time() < deadline:
            g.poll(200)
            events, _ = g.events()
            for w in watches:
                for e in events:
                    x = w.decode(e)
                    if x and x.slot >= 0:
                        print(f"{w.name}[{x.slot}] {x.before.hex()} -> {x.after.hex()} by {x.rip:#x} {syms.name(x.rip)}")
    finally:
        for w in watches:
            w.stop()
