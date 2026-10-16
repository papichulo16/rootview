"""Write-watch a range of kernel memory and decode each write into the slot it hit.

The range is hooked by physical frame (EPT write traps with capture), so a
write through any alias of the same memory is seen, e.g. the IDT through
idt_table's writable mapping as well as IDTR's read-only one. Writes made
before the watch went on raise nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest, HookEvent

PAGE = 4096


@dataclass(frozen=True)
class Write:
    va: int  # the written address, through the watched range's own mapping
    slot: int  # (va - start) // slot_size, or -1 outside [start, start + length)
    before: bytes  # the slot's bytes before and after the write
    after: bytes
    rip: int  # the instruction that wrote
    complete: bool  # False: the vcpu never stepped past the write, after == before


class MemWatch:
    def __init__(self, g: Guest, name: str, start: int, length: int, slot_size: int = 8) -> None:
        """Watches [start, start + length), seen as slot_size-byte slots (8 for
        a pointer table, 16 for IDT gates). slot_size divides 16, the capture window."""
        if 16 % slot_size or start % slot_size:
            raise ValueError("slots must be aligned and divide the 16-byte capture window")
        self.g, self.name = g, name
        self.start, self.length, self.slot_size = start, length, slot_size
        self.frames: dict[int, int] = {}  # gfn -> the page's va
        self.hooks: list[str] = []

    def __enter__(self) -> MemWatch:
        self.start_watching()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start_watching(self) -> None:
        g = self.g
        with g.snapshot():
            for va in range(self.start & ~(PAGE - 1), self.start + self.length, PAGE):
                self.frames[g.translate(va) >> 12] = va
            for i, gfn in enumerate(self.frames):
                hook = f"{self.name}:{i}"
                g.hook_mem_gfn(hook, gfn, "w", capture=True)
                self.hooks.append(hook)

    def stop(self) -> None:
        for hook in self.hooks:
            self.g.hook_remove(hook)
        self.hooks.clear()

    def decode(self, e: HookEvent) -> Write | None:
        """The write e made, if it's one of this watch's events."""
        if not e.name.startswith(f"{self.name}:") or not e.captured:
            return None
        page = self.frames.get(e.mem_gpa >> 12)
        if page is None:
            return None
        va = page + (e.mem_gpa & (PAGE - 1))
        if not self.start <= va < self.start + self.length:
            return Write(va, -1, b"", b"", e.rip, e.after_ok)
        slot = (va - self.start) // self.slot_size
        at = (self.start + slot * self.slot_size) & 15  # the slot's place in the 16-aligned window
        return Write(va, slot, e.before[at:at + self.slot_size], e.after[at:at + self.slot_size], e.rip, e.after_ok)

    def poll(self, timeout_ms: int = 100) -> tuple[list[Write], list[HookEvent]]:
        """Pumps events: this watch's writes, decoded, and every other event drained."""
        self.g.poll(timeout_ms)
        events, _ = self.g.events()
        writes, other = [], []
        for e in events:
            w = self.decode(e)
            if w:
                writes.append(w)
            else:
                other.append(e)
        return writes, other
