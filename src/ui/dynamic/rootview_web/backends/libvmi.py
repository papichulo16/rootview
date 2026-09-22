"""The real introspection backend. Not implemented yet.

This is the module to fill in. It is wired into the web server already: set
``ROOTVIEW_BACKEND=libvmi`` and every page, endpoint and event will be driven by
whatever these four methods return. Nothing else in the web server needs to
change.

Each method below documents what it has to produce. Implement them in whatever
order is convenient -- ``list_vms`` first is usually easiest, since it makes the
guests appear in the interface before any eBPF parsing works.

The methods raise :class:`NotImplementedError` until they are written. That is
deliberate: an empty list would be indistinguishable from "this guest is clean",
and RootView must never imply a clean result it did not actually establish.
"""

from __future__ import annotations

from rootview_web.backends.base import IntrospectionBackend
from rootview_web.schemas import BpfSnapshot, ScanResult, VM


class LibVMIBackend(IntrospectionBackend):
    """Reads guest kernel memory from the KVM host via LibVMI."""

    def __init__(self, **options: object) -> None:
        """Store whatever configuration the engine ends up needing.

        Left open on purpose -- socket paths, a kernel profile directory, which
        hypervisor to talk to. Add explicit keyword arguments as the shape of
        the real thing becomes clear, and surface them through
        :class:`rootview_web.config.Settings` so they can be set from the
        environment.
        """
        self.options = options

    @property
    def connected(self) -> bool:
        """Whether the engine can currently read a guest.

        Return ``True`` only when introspection is genuinely working. The
        interface uses this to decide whether it is allowed to show an
        all-clear, so a wrong answer here produces a false sense of safety.
        """
        return False

    async def startup(self) -> None:
        """Acquire resources. Called once when the web server starts.

        Initialise LibVMI, open the guest, load kernel symbols. Raise
        :class:`~rootview_web.backends.base.BackendError` if the engine cannot
        start; the web server stays up and reports the failure.
        """
        raise NotImplementedError("LibVMIBackend.startup is not implemented yet")

    async def shutdown(self) -> None:
        """Release resources. Called once when the web server stops."""
        raise NotImplementedError("LibVMIBackend.shutdown is not implemented yet")

    async def list_vms(self) -> list[VM]:
        """Return every guest this host can introspect.

        Each :class:`~rootview_web.schemas.VM` needs a stable ``vm_id`` (used in
        every URL), a display ``name``, a ``state``, and a
        :class:`~rootview_web.schemas.GuestInfo` carrying the kernel release,
        architecture, and whether a matching kernel profile was found. Set
        ``profile_loaded=False`` when symbols could not be resolved -- the
        interface warns the user that findings for that guest are unreliable.
        """
        raise NotImplementedError("LibVMIBackend.list_vms is not implemented yet")

    async def get_vm(self, vm_id: str) -> VM:
        """Return one guest.

        Raise :class:`~rootview_web.backends.base.UnknownVMError` for an
        unrecognised id; the API turns that into a 404.
        """
        raise NotImplementedError("LibVMIBackend.get_vm is not implemented yet")

    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        """Read the guest's current eBPF program and map state.

        Raw introspection with no detection logic applied. Walk the guest's
        ``prog_idr`` and ``map_idr`` and build
        :class:`~rootview_web.schemas.BpfProgram` and
        :class:`~rootview_web.schemas.BpfMap` records.

        The field that carries the whole point of the project is
        ``visibility``:

        * ``VISIBLE``   -- the hypervisor and the guest agree the object exists
        * ``HIDDEN``    -- the hypervisor sees it, the guest does not report it
        * ``UNCHECKED`` -- no guest-side comparison was available

        Use ``UNCHECKED`` whenever the guest was not actually asked. Reporting
        ``HIDDEN`` without a real comparison manufactures a critical finding out
        of nothing.

        A powered-off guest should return an empty snapshot rather than raising:
        "no eBPF state" is a true answer for a guest that is not running.
        """
        raise NotImplementedError("LibVMIBackend.snapshot is not implemented yet")

    async def scan(self, vm_id: str) -> ScanResult:
        """Take a snapshot and run the detection rules over it.

        The rules already exist and are backend-agnostic::

            from rootview_web.detection import run_rules

            snap = await self.snapshot(vm_id)
            detections = run_rules(snap)

        Populate ``programs_examined`` and ``maps_examined`` from the snapshot,
        and put anything that went wrong mid-scan into ``errors`` rather than
        raising -- a partial result is more useful than none.
        """
        raise NotImplementedError("LibVMIBackend.scan is not implemented yet")
