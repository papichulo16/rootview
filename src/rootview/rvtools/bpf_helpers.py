"""The kernel helpers an eBPF program calls, decoded from its instructions."""

from __future__ import annotations

from rootview.rvprim import Guest, RootviewError

BPF_CALL = 0x85
INSNS_MAX = 1 << 17


class Helpers:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.base = g.sym("__bpf_call_base")
        self.insns = g.field("bpf_prog", "insnsi").offset
        self.names: dict[int, str] = {}

    def of(self, prog: int, count: int) -> tuple[str, ...]:
        raw = self.g.read(prog + self.insns, 8 * min(count, INSNS_MAX))
        found = []
        for i in range(0, len(raw), 8):
            if raw[i] != BPF_CALL or raw[i + 1] >> 4:
                continue
            found.append(self.name(self.base + int.from_bytes(raw[i + 4:i + 8], "little", signed=True)))
        return tuple(dict.fromkeys(found))

    def name(self, addr: int) -> str:
        if addr not in self.names:
            try:
                sym, off = self.g.sym_at(addr)
                self.names[addr] = sym.name if not off else f"{sym.name}+{off:#x}"
            except RootviewError:
                self.names[addr] = f"{addr:#x}"
        return self.names[addr]
