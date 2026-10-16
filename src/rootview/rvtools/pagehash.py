"""Per-page SHA-256 of kernel memory, and comparing two sets of hashes.

Per page because a clean kernel rewrites its own text after boot (static
keys, ftrace, alternatives): a whole-section hash would never match, while a
page-level comparison names only the pages that moved.
"""

from __future__ import annotations

import hashlib

from rootview.rvprim import Guest, RootviewError

PAGE = 4096
#: the kernel's text and rodata, as kallsyms bounds them
REGIONS = {"text": ("_stext", "_etext"), "rodata": ("__start_rodata", "__end_rodata")}


def pages(start: int, end: int):
    """(va, length) for [start, end) a page at a time; an unaligned first or
    last page holds only the region's own bytes."""
    va = start
    while va < end:
        nxt = min((va & ~(PAGE - 1)) + PAGE, end)
        yield va, nxt - va
        va = nxt


def hash_range(g: Guest, start: int, end: int) -> dict[int, str | None]:
    """va -> hex SHA-256 of that page's bytes, None where it couldn't be read."""
    out: dict[int, str | None] = {}
    for va, n in pages(start, end):
        try:
            out[va] = hashlib.sha256(g.read(va, n)).hexdigest()
        except RootviewError:
            out[va] = None
    return out


def hash_kernel(g: Guest) -> dict[str, dict[int, str | None]]:
    """Every region in REGIONS, hashed in one snapshot: region -> hash_range()."""
    with g.snapshot():
        return {name: hash_range(g, g.sym(s), g.sym(e)) for name, (s, e) in REGIONS.items()}


def compare(before: dict[int, str | None], after: dict[int, str | None]) -> list[tuple[int, str]]:
    """(va, how) for each page that differs: modified, unreadable (readable
    before, not now), readable (the reverse), added or removed."""
    out = []
    for va in sorted(before.keys() | after.keys()):
        if va not in after:
            out.append((va, "removed"))
        elif va not in before:
            out.append((va, "added"))
        elif before[va] != after[va]:
            how = "unreadable" if after[va] is None else "readable" if before[va] is None else "modified"
            out.append((va, how))
    return out
