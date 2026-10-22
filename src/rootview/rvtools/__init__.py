"""Tooling on top of rootview.rvprim for a detection engine to build on.

Each tool enumerates or decodes one part of the guest kernel and reports
facts. None of them decides what is malicious.

  common     attach(), Layout (struct decoding), Symbols, raw readers
  tasks      task_structs through each structure that holds them
  modules    struct modules through each structure that holds them, carving
  tables     sys_call_table, IDT gates, LSTAR, and where a pointer lands
  ftrace     dyn_ftrace records and their call sites
  pagehash   per-page hashes of kernel memory, and comparing them
  memwatch   write-watch a memory range and decode the writes
  clock      the guest's boot time, and boot-relative stamps as dates
  ebpf       loaded eBPF programs, maps and attachments: decoded and analyzed
"""

from rootview.rvtools.clock import Clock
from rootview.rvtools.common import Layout, Symbols, attach, is_kernel_va
from rootview.rvtools.ftrace import Ftrace
from rootview.rvtools.memwatch import MemWatch
from rootview.rvtools.modules import Modules
from rootview.rvtools.tables import Tables
from rootview.rvtools.tasks import Tasks

__all__ = ["Clock", "Ftrace", "Layout", "MemWatch", "Modules", "Symbols", "Tables", "Tasks", "attach", "is_kernel_va"]
