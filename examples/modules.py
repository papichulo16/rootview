"""Every struct module, which structures reach it, and its own symbols.

    python examples/modules.py [vm] [--carve]
"""

import sys

from rootview.rvtools import Modules, attach
from rootview.rvtools.modules import SOURCES, STATES

args = [a for a in sys.argv[1:] if not a.startswith("--")]
carve = "--carve" in sys.argv
with attach(args[0] if args else None) as g:
    mods = Modules(g)
    found, errors = mods.sources(carve=carve)
    infos = {m: mods.info(m) for m in found}

shown = SOURCES if carve else SOURCES[:3]
print(f"{'NAME':<24} {'STATE':<8} {'TEXT':<30} {'SYMS IN TEXT':>12}  SOURCES")
for m, srcs in sorted(found.items(), key=lambda kv: infos[kv[0]].name):
    i = infos[m]
    syms = "?" if i.nsyms is None else f"{i.nsyms_in_text}/{i.nsyms}"
    marks = " ".join(s if s in srcs else "-" * len(s) for s in shown)
    print(f"{i.name:<24} {STATES[i.state] if i.state < 4 else i.state:<8} {i.text_base:#x}+{i.text_size:<#10x} "
          f"{syms:>12}  {marks}")
print(f"\n{len(found)} modules: " + ", ".join(f"{s}={sum(s in v for v in found.values())}" for s in shown))
for src, err in errors.items():
    print(f"{src} failed: {err}")
