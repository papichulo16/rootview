"""What needs a Guest: reading programs, maps, attachments and holders, and
naming what programs point at.

  progs     Progs: prog_idr, struct bpf_prog and bpf_prog_aux as ProgInfo, instructions
  maps      Maps: map_idr, struct bpf_map as MapInfo
  attach    where programs are attached: cgroups, bpf_links, trace events, perf events
  fds       Fds: every process's eBPF and perf fds
  holders   Holders: the processes holding each program or map
  resolve   Resolver: call targets via kallsyms, map pointers via struct bpf_map
"""

from rootview.rvtools.ebpf.guest.attach import Attachment, attachments
from rootview.rvtools.ebpf.guest.fds import Fd, Fds
from rootview.rvtools.ebpf.guest.holders import Holder, Holders
from rootview.rvtools.ebpf.guest.maps import MapInfo, Maps
from rootview.rvtools.ebpf.guest.progs import ProgInfo, Progs
from rootview.rvtools.ebpf.guest.resolve import MapRef, Resolver

__all__ = ["Attachment", "Fd", "Fds", "Holder", "Holders", "MapInfo", "MapRef", "Maps", "ProgInfo", "Progs",
           "Resolver", "attachments"]
