"""struct modules, reached through each structure the kernel keeps them in.

  module_list  the modules list (what lsmod and /proc/modules walk)
  mod_tree[i]  each copy of the mod_tree latch tree (address lookups use it)
  carve        mapped pages of the module area that hold a plausible struct module

``info()`` decodes one, including how many of its own kallsyms fall in its text.
"""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprimitives import Guest, RootviewError
from rootview.rvtools.common import LIST_POISON1, LIST_POISON2, Layout, is_kernel_va, qwords, read_u32, read_u64

SOURCES = ("module_list", "mod_tree[0]", "mod_tree[1]", "carve")
STATES = ("live", "coming", "going", "unformed")
# x86_64: modules map between the end of the image mapping and the fixmap
MODULES_LOW = 0xFFFFFFFFA0000000
MODULES_END = 0xFFFFFFFFFF000000
PAGE = 4096


@dataclass(frozen=True)
class ModuleInfo:
    addr: int
    name: str
    state: int  # enum module_state: index into STATES
    text_base: int
    text_size: int
    nsyms: int | None  # mod->kallsyms entries; None if unreadable
    nsyms_in_text: int | None  # of those, how many fall inside the text


class Modules:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.layout = Layout(g, "module", "list", "name", "state", "mkobj.mod", "kallsyms")
        self.text_base_off, self.text_size_off = self._text_offsets()
        self.rb_size = g.type_size("rb_node")
        self.node_off = g.field("mod_tree_node", "node").offset
        self.mod_off = g.field("mod_tree_node", "mod").offset

    def _text_offsets(self) -> tuple[int, int]:
        """6.4 split the layouts into mem[MOD_MEM_NUM_TYPES]; before that it's
        core_layout. Both sizes are unsigned int."""
        g = self.g
        try:
            mem = g.field("module", "mem").offset
        except RootviewError:
            return g.field("module", "core_layout.base").offset, g.field("module", "core_layout.text_size").offset
        entry = mem + g.enum_value("MOD_TEXT", "mod_mem_type") * g.type_size("module_memory")
        return entry + g.field("module_memory", "base").offset, entry + g.field("module_memory", "size").offset

    def module_list(self) -> list[int]:
        return self.g.list_off(self.g.sym("modules"), self.layout.off("list"))

    def mod_tree(self, idx: int) -> list[tuple[int, int]]:
        """(module, mod_tree_node) for each node of tree[idx]. A node normally
        sits inside the struct module it names."""
        g = self.g
        root = g.sym("mod_tree") + g.field("mod_tree_root", "root.tree").offset + 8 * idx
        out = []
        for rb in g.rbtree(root):
            node = rb - idx * self.rb_size - self.node_off  # node[idx] of the latch_tree_node
            out.append((read_u64(g, node + self.mod_off), node))
        return out

    def looks_like_module(self, mod: int) -> bool:
        """mkobj.mod points back, a known state, a printable name, and list
        pointers that are kernel addresses, its own head, or list_del's poison."""
        lo = self.layout
        try:
            buf = self.g.read(mod, max(lo.off("name") + lo.fields["name"].size, lo.off("list") + 16,
                                       lo.off("state") + 4, lo.off("mkobj.mod") + 8))
        except RootviewError:
            return False
        head = mod + lo.off("list")
        nxt, prv = qwords(buf[lo.off("list"):lo.off("list") + 16])
        ok = all(p in (head, LIST_POISON1, LIST_POISON2) or is_kernel_va(p) for p in (nxt, prv))
        name = buf[lo.off("name"):].split(b"\0", 1)[0]
        return (lo.get(buf, "mkobj.mod") == mod and lo.get(buf, "state") < len(STATES) and ok
                and 0 < len(name) < lo.fields["name"].size and all(0x20 <= c < 0x7F for c in name))

    def carve(self, start: int | None = None, end: int = MODULES_END) -> list[int]:
        """Every mapped page in [start, end) searched for a struct module: the
        qword at mod + mkobj.mod holds mod. Slow (~10s over the whole area)."""
        g = self.g
        if start is None:
            start = max(MODULES_LOW, (g.sym("_end") + 0x1FFFFF) & ~0x1FFFFF)
        back = self.layout.off("mkobj.mod")
        found = []
        for va in range(start, end, PAGE):
            try:
                g.translate(va)  # the area is mostly unmapped, and a failed translate is far cheaper than a read
                page = g.read(va, PAGE)
            except RootviewError:
                continue
            for i, q in enumerate(qwords(page)):
                if q == va - back + 8 * i and self.looks_like_module(q):
                    found.append(q)
        return found

    def sources(self, carve: bool = False) -> tuple[dict[int, set[str]], dict[str, str]]:
        """Every source, in one snapshot: module -> the sources that reached it,
        and source -> why it failed."""
        found: dict[int, set[str]] = {}
        errors: dict[str, str] = {}
        runs = [("module_list", self.module_list),
                ("mod_tree[0]", lambda: [m for m, _ in self.mod_tree(0)]),
                ("mod_tree[1]", lambda: [m for m, _ in self.mod_tree(1)])]
        if carve:
            runs.append(("carve", self.carve))
        with self.g.snapshot():
            for name, fn in runs:
                try:
                    for m in fn():
                        found.setdefault(m, set()).add(name)
                except RootviewError as e:
                    errors[name] = str(e)
        return found, errors

    def info(self, mod: int) -> ModuleInfo:
        lo, g = self.layout, self.g
        buf = lo.read(g, mod)
        b, s = self.text_base_off, self.text_size_off
        base = int.from_bytes(buf[b:b + 8], "little")
        size = int.from_bytes(buf[s:s + 4], "little")
        nsyms = in_text = None
        try:
            nsyms, in_text = self._count_syms(lo.get(buf, "kallsyms"), base, size)
        except RootviewError:
            pass
        return ModuleInfo(mod, lo.get(buf, "name"), lo.get(buf, "state"), base, size, nsyms, in_text)

    def _count_syms(self, ks: int, base: int, size: int) -> tuple[int, int]:
        """mod->kallsyms: Elf64_Sym entries are 24 bytes, st_value at 8."""
        g = self.g
        if not is_kernel_va(ks):
            raise RootviewError(f"kallsyms is {ks:#x}")
        symtab = read_u64(g, ks + g.field("mod_kallsyms", "symtab").offset)
        num = read_u32(g, ks + g.field("mod_kallsyms", "num_symtab").offset)
        if num > 1 << 18 or (num and not is_kernel_va(symtab)):
            raise RootviewError(f"{num} symbols at {symtab:#x}")
        values = qwords(g.read(symtab, 24 * num))[1::3] if num else ()
        return num, sum(base <= v < base + size for v in values)
