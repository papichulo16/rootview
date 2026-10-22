"""The eBPF instruction set: decoding bytes and printing instructions. No guest needed.

  opcodes   opcode fields and their names
  insn      Insn and decode()
  disasm    line() and listing(), in bpftool's syntax
"""

from rootview.rvtools.ebpf.isa.disasm import line, listing, public
from rootview.rvtools.ebpf.isa.insn import SLOT, Insn, decode

__all__ = ["SLOT", "Insn", "decode", "line", "listing", "public"]
