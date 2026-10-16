"""ftrace's patch sites: every dyn_ftrace record and what its call site holds.

Every function built with -mfentry starts with a 5-byte call to __fentry__,
which boot rewrites to a nop and ftrace rewrites back into a call for each
function an ftrace_ops attaches to. Records live in ftrace_page blocks
chained from ftrace_pages_start.
"""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.common import Layout, is_kernel_va, read_u64

NOP5 = bytes((0x0F, 0x1F, 0x44, 0x00, 0x00))
# FTRACE_FL_* when BTF doesn't have them: the values 5.x through 6.18 use
FALLBACK_BITS = {"enabled": 1 << 31, "ipmodify": 1 << 26, "direct": 1 << 24}


@dataclass(frozen=True)
class Record:
    index: int
    ip: int  # the patch site
    flags: int  # dyn_ftrace.flags, raw
    enabled: bool
    ipmodify: bool
    direct: bool
    site: bytes | None  # the 5 bytes at ip, None if unreadable
    target: int  # where a call/jmp at ip goes, 0 for anything else

    @property
    def nop(self) -> bool:
        return self.site == NOP5


class Ftrace:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.page = Layout(g, "ftrace_page", "next", "records", "index")
        self.rec = Layout(g, "dyn_ftrace", "ip", "flags")
        self.bits = self._bits()

    def _bits(self) -> dict[str, int]:
        """FTRACE_FL_* live in an anonymous enum."""
        try:
            return {n: self.g.enum_value(f"FTRACE_FL_{n.upper()}") for n in FALLBACK_BITS}
        except RootviewError:
            return dict(FALLBACK_BITS)

    def records(self, only_active: bool = True) -> tuple[list[Record], int]:
        """The records, and how many there are in all. With only_active, just
        the ones enabled or whose site isn't the nop (a handful, not ~50k)."""
        g, page, rec = self.g, self.page, self.rec
        out, total = [], 0
        pg = read_u64(g, g.sym("ftrace_pages_start"))
        for _ in range(65536):
            if not pg:
                break
            if not is_kernel_va(pg):
                raise RootviewError(f"ftrace page {pg:#x} isn't a kernel address")
            hdr = page.read(g, pg)
            count = max(page.get(hdr, "index"), 0)
            raw = g.read(page.get(hdr, "records"), count * rec.size) if count else b""
            for i in range(count):
                r = raw[i * rec.size:(i + 1) * rec.size]
                record = self._record(total + i, rec.get(r, "ip"), rec.get(r, "flags"))
                if not only_active or record.enabled or (record.site is not None and not record.nop):
                    out.append(record)
            total += count
            pg = page.get(hdr, "next")
        return out, total

    def _record(self, index: int, ip: int, flags: int) -> Record:
        try:
            site = self.g.read(ip, 5)
        except RootviewError:
            site = None  # a site gone with freed init memory
        target = 0
        if site and site[0] in (0xE8, 0xE9):  # call / jmp rel32
            target = ip + 5 + int.from_bytes(site[1:5], "little", signed=True)
        b = self.bits
        return Record(index, ip, flags, bool(flags & b["enabled"]), bool(flags & b["ipmodify"]),
                      bool(flags & b["direct"]), site, target)
