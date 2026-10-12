"""Hash kernel text and rodata per page, save it, and compare later.

    python examples/pagehash.py save [vm] [file]      default file: pagehash.json
    python examples/pagehash.py compare [vm] [file]
"""

import json
import sys

from rootview.rvtools import Symbols, attach, pagehash

mode, vm, path = (sys.argv[1:] + [None, None, None])[:3]
path = path or "pagehash.json"
if mode not in ("save", "compare"):
    sys.exit(__doc__)

with attach(vm) as g:
    now = pagehash.hash_kernel(g)
    syms = Symbols(g)

if mode == "save":
    with open(path, "w") as f:
        json.dump({r: {hex(va): h for va, h in pages.items()} for r, pages in now.items()}, f)
    print(f"saved {sum(map(len, now.values()))} page hashes to {path}")
    sys.exit()

with open(path) as f:
    before = {r: {int(va, 16): h for va, h in pages.items()} for r, pages in json.load(f).items()}
for region in now:
    changes = pagehash.compare(before.get(region, {}), now[region])
    print(f"{region}: {len(now[region])} pages, {len(changes)} differ")
    for va, how in changes:
        print(f"  {how:<10} {va:#x} {syms.name(va)}")
