"""ftrace records that are enabled or whose call site isn't the nop.

    python examples/ftrace.py [vm]
"""

import sys

from rootview.rvtools import Ftrace, Symbols, attach

with attach(sys.argv[1] if len(sys.argv) > 1 else None) as g:
    syms = Symbols(g)
    with g.snapshot():
        records, total = Ftrace(g).records()

print(f"{total} records, {len(records)} enabled or patched")
for r in records:
    flags = ",".join(n for n in ("enabled", "ipmodify", "direct") if getattr(r, n))
    site = "unreadable" if r.site is None else "nop" if r.nop else r.site.hex()
    target = f"-> {r.target:#x} {syms.name(r.target)}" if r.target else ""
    print(f"  {r.ip:#x} {syms.name(r.ip):<40} {flags:<24} {site:<12} {target}")
