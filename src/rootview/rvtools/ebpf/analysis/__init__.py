"""Analysis of one program's instructions. No guest needed.

  calls   helper, kfunc, subprogram and tail call sites
  refs    ld_imm64 sites: maps, map values, constants, function pointers
  cfg     basic blocks, edges, subprograms, loops, unreachable code
"""

from rootview.rvtools.ebpf.analysis.calls import Call, calls
from rootview.rvtools.ebpf.analysis.cfg import Block, Cfg, build
from rootview.rvtools.ebpf.analysis.refs import Ref, refs

__all__ = ["Block", "Call", "Cfg", "Ref", "build", "calls", "refs"]
