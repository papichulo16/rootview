"""Loaded eBPF programs: read out of the guest, decoded, disassembled and
analyzed.

  isa        the instruction set: decode bytes, print instructions (no guest)
  analysis   calls, ld_imm64 references, control-flow graph (no guest)
  guest      Progs, Maps and attachments() read the guest; Resolver names calls and maps
  program    Program and analyze(): all of it for one bpf_prog
"""

from rootview.rvtools.ebpf.guest import Attachment, MapInfo, MapRef, Maps, ProgInfo, Progs, Resolver, attachments
from rootview.rvtools.ebpf.program import CallSite, Program, analyze

__all__ = ["Attachment", "CallSite", "MapInfo", "MapRef", "Maps", "ProgInfo", "Program", "Progs", "Resolver",
           "analyze", "attachments"]
