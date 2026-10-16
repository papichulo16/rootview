"""The libvmi backend and engine routes over a fake rootview.rvprim."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from rootview_web.app import create_app
from rootview_web.backends.libvmi import LibVMIBackend
from rootview_web.config import Settings
from rootview_web.engine import GuestPool, bpf
from rootview_web.schemas import BpfMapType, BpfProgType, VMState

KTEXT = 0xFFFFFFFF81000000


class RootviewError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    name: str
    memory_mb: int = 1024
    cpus: int = 1
    disk_image: str = ""
    cdrom: str = ""
    network: str = "user"
    display: str = "none"
    kvm: bool = True
    kvmi_enabled: bool = True
    extra_args: str = ""


@dataclass(frozen=True)
class Vm:
    name: str
    config: Config
    running: bool = False
    kvmi: bool = False
    pid: int | None = None
    started_at: int | None = None
    qmp_socket: str = ""
    monitor_socket: str = ""
    kvmi_socket: str = ""
    log_path: str = ""


@dataclass
class FakeGuest:
    name: str
    profiled: bool = True
    hooks_: list = field(default_factory=list)
    mem: dict = field(default_factory=dict)
    closed: bool = False

    def load_profile(self):
        if self.name == "noprof":
            raise RootviewError("no BTF")

    def close(self):
        self.closed = True

    def info(self):
        return SimpleNamespace(banner="Linux", release="6.8.0", version=(6, 8, 0), image=(KTEXT, KTEXT + 0x1000000),
                               nsyms=100, btf_types=50, init_task=KTEXT + 0x10, btf_va=KTEXT + 0x800000,
                               btf_by_symbol=True)

    def field(self, type, path):
        if type != "task_struct":
            raise RootviewError(f"no type {type}")
        return SimpleNamespace(offset=0x80, size=8, bit_off=0, bit_size=0, kind="ptr", type=7, ref=9)

    def btf_type(self, id):
        return SimpleNamespace(kind={7: "ptr", 9: "struct"}[id], name={7: "", 9: "mm_struct"}[id])

    def read_field(self, type, path, addr):
        return SimpleNamespace(kind="ptr", value=KTEXT + 0x40, length=0, enum_name=None)

    def tasks(self):
        return [SimpleNamespace(addr=KTEXT + 0x2000, pid=1, tgid=1, comm="<script>systemd")]

    def read(self, va, n):
        return bytes(range(n))

    read_phys = read_virt = read

    def write_phys(self, pa, data):
        self.mem[pa] = data

    def regs(self):
        return {"rip": KTEXT + 5, "cr3": 0x1000}

    def reg(self, name):
        if name != "cr3":
            raise RootviewError(f"unknown register '{name}'")
        return 0x1000

    def hook_desc(self, name, table):
        self.hooks_.append(SimpleNamespace(name=name, kind="descriptor", reg="", vaddr=0, cpuid_leaf=None,
                                           descriptor=table, mem_gfn=0, access="", capture=False))

    def hooks(self):
        return self.hooks_

    def poll(self, ms):
        pass

    def events(self):
        e = SimpleNamespace(seq=0, kind="mem", name="w", vcpu=0, vaddr=0, old_value=0, new_value=0, cpuid_leaf=0,
                            cpuid_subleaf=0, descriptor="", desc_is_write=False, mem_gpa=0x1234020, mem_access="w",
                            rip=KTEXT + 9, rip_sym="f", rip_off=9, captured=True, after_ok=True, window=0x1234020,
                            before=b"\0" * 16, after=b"\xff" * 16)
        return [e], 3

    def snapshot(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


class FakePrim:
    RootviewError = RootviewError

    def __init__(self, loadable=True):
        self.loadable = loadable
        self.vms = {
            "web": Vm("web", Config("web"), running=True, kvmi=True, pid=42),
            "nokvmi": Vm("nokvmi", Config("nokvmi"), running=True, pid=43),
            "noprof": Vm("noprof", Config("noprof"), running=True, kvmi=True, pid=44),
            "off": Vm("off", Config("off")),
        }
        self.guests = {}

    def lib(self):
        if not self.loadable:
            raise RootviewError("could not load librootview.so")

    def set_base(self, d):
        pass

    def list_vms(self):
        return list(self.vms.values())

    def inspect_vm(self, name):
        if name not in self.vms:
            raise RootviewError(f"vm '{name}' does not exist")
        return self.vms[name]

    def create_vm(self, name, **kw):
        self.vms[name] = Vm(name, Config(name, **kw))

    def start_vm(self, name):
        self.vms[name] = replace(self.inspect_vm(name), running=True, kvmi=True, pid=7)

    def stop_vm(self, name):
        self.vms[name] = replace(self.inspect_vm(name), running=False, kvmi=False, pid=None)

    restart_vm = start_vm

    def destroy_vm(self, name, force=False):
        del self.vms[name]

    def Guest(self, name, profile=True):
        vm = self.inspect_vm(name)
        if not (vm.running and vm.kvmi):
            raise RootviewError(f"vm '{name}' is not running")
        g = self.guests[name] = FakeGuest(name, profiled=name != "noprof")
        return g


class FakeBpf:
    def __init__(self, g):
        pass

    def programs(self):
        return [SimpleNamespace(id=3, name="probe", type="BPF_PROG_TYPE_KPROBE", tag=bytes(range(8)), jited=True,
                                insns=10, jited_len=64, map_ids=(5,), helpers=(), attach=(), uid=0,
                                holders=((1, "systemd"),)),
                SimpleNamespace(id=4, name="new", type="BPF_PROG_TYPE_FUTURE", tag=b"\0" * 8, jited=False,
                                insns=1, jited_len=0, map_ids=(), helpers=(), attach=(), uid=None, holders=()),
                SimpleNamespace(id=111, name="handle_getdents", type="BPF_PROG_TYPE_TRACEPOINT", tag=b"\1" * 8,
                                jited=True, insns=200, jited_len=900, map_ids=(5,),
                                helpers=("bpf_probe_read_user", "bpf_probe_write_user"),
                                attach=("syscalls:sys_exit_getdents64",), uid=0, holders=((6612, "pidhide"),))]

    def maps(self):
        return [SimpleNamespace(id=5, name="m", type="BPF_MAP_TYPE_HASH", key_size=4, value_size=8, max_entries=16)]


def client(prim, **settings):
    app = create_app(Settings(backend="none", scan_interval=60, **settings))
    pool = GuestPool(prim=prim)
    backend = LibVMIBackend(pool)
    app.state.engine = pool
    app.state.backend = backend
    app.state.scanner.backend = backend
    return TestClient(app)


@pytest.fixture
def prim(monkeypatch):
    monkeypatch.setattr(bpf, "Bpf", FakeBpf)
    return FakePrim()


@pytest.fixture
def c(prim):
    with client(prim) as c:
        yield c


def test_unavailable_engine_is_reported_not_hidden():
    with client(FakePrim(loadable=False)) as c:
        assert c.get("/api/health").json()["backend_connected"] is False
        assert "No introspection backend connected" in c.get("/dashboard").text
        assert c.get("/api/vms").status_code == 502
        assert c.get("/api/vms/web/registers").status_code == 503


def test_guest_states(c):
    vms = {v["vm_id"]: v for v in c.get("/api/vms").json()}
    assert vms["web"]["state"] == VMState.RUNNING
    assert vms["web"]["guest"] == {"kernel_release": "6.8.0", "architecture": "x86_64", "profile_loaded": True}
    assert vms["noprof"]["guest"]["profile_loaded"] is False
    assert vms["nokvmi"]["state"] == VMState.UNREACHABLE
    assert vms["off"]["state"] == VMState.SHUT_OFF


def test_snapshot_maps_kernel_enums(c):
    snap = c.get("/api/vms/web/snapshot").json()
    probe, new, rootkit = snap["programs"]
    assert (probe["prog_type"], probe["tag"], probe["bytes_xlated"], probe["map_ids"]) == (
        BpfProgType.KPROBE, "0001020304050607", 80, [5])
    assert new["prog_type"] == BpfProgType.UNKNOWN
    assert snap["maps"][0]["map_type"] == BpfMapType.HASH
    assert probe["visibility"] == "unchecked"


def test_snapshot_without_profile_is_an_error(c):
    r = c.get("/api/vms/noprof/snapshot")
    assert r.status_code == 502 and "no BTF" in r.json()["detail"]


def test_powered_off_snapshot_is_empty(c):
    assert c.get("/api/vms/off/snapshot").json()["programs"] == []


def test_memory_comes_back_as_hex(c):
    r = c.get("/api/vms/web/memory", params={"addr": hex(KTEXT), "length": 4, "space": "phys"}).json()
    assert r == {"space": "phys", "addr": hex(KTEXT), "data": "00010203"}
    assert c.get("/api/vms/web/memory", params={"addr": "zz", "length": 4}).status_code == 422
    assert c.get("/api/vms/web/memory", params={"addr": "0x0", "length": 1 << 20}).status_code == 422


def test_registers_are_hex_strings(c):
    assert c.get("/api/vms/web/registers").json() == {"rip": hex(KTEXT + 5), "cr3": "0x1000"}
    assert c.get("/api/vms/web/registers/cr3").json() == {"name": "cr3", "value": "0x1000"}
    assert c.get("/api/vms/web/registers/bogus").status_code == 502


def test_kernel_info(c):
    info = c.get("/api/vms/web/kernel").json()
    assert info["init_task"] == hex(KTEXT + 0x10) and info["image"][0] == hex(KTEXT)


def test_writes_are_off_by_default(c):
    body = {"space": "phys", "addr": "0x1000", "data": "90"}
    assert c.put("/api/vms/web/memory", json=body).status_code == 403


def test_writes_when_allowed(prim):
    with client(prim, allow_writes=True) as c:
        assert c.put("/api/vms/web/memory", json={"space": "phys", "addr": "0x1000", "data": "9090"}).status_code == 204
        assert prim.guests["web"].mem == {0x1000: b"\x90\x90"}
        r = c.put("/api/vms/web/memory", json={"space": "kernel", "addr": "0x1000", "data": "90"})
        assert r.status_code == 422


def test_cross_origin_mutation_is_refused(c):
    assert c.post("/api/vms/web/stop", headers={"origin": "http://evil.example"}).status_code == 403
    assert c.post("/api/vms/web/pause", headers={"origin": "http://evil.example"}).status_code == 403


def test_hooks(c):
    r = c.post("/api/vms/web/hooks", json={"name": "idt", "kind": "descriptor", "table": "idtr"})
    assert r.status_code == 201 and r.json()[0]["descriptor"] == "idtr"
    assert c.post("/api/vms/web/hooks", json={"name": "x", "kind": "breakpoint"}).status_code == 422
    ev = c.get("/api/vms/web/hooks/events").json()
    assert ev["dropped"] == 3
    assert ev["events"][0]["after"] == "ff" * 16 and ev["events"][0]["rip"] == hex(KTEXT + 9)


def test_lifecycle(c, prim):
    r = c.post("/api/vms", json={"name": "new", "cpus": 2, "network": "none"})
    assert r.status_code == 201 and r.json()["config"]["cpus"] == 2
    assert c.post("/api/vms", json={"name": "bad", "network": "bogus"}).status_code == 422
    assert c.post("/api/vms/new/start").json()["running"] is True
    c.get("/api/vms/new/registers")
    g = prim.guests["new"]
    assert c.post("/api/vms/new/stop").json()["running"] is False
    assert g.closed
    assert c.delete("/api/vms/new").status_code == 204
    assert c.get("/api/vms/new/details").status_code == 502


def test_unknown_guest_is_404(c):
    assert c.get("/api/vms/nope/registers").status_code == 404


def test_engine_status_and_listing(c):
    assert c.get("/api/engine").json() == {"connected": True, "allow_writes": False}
    vms = {v["name"]: v for v in c.get("/api/engine/vms").json()}
    assert vms["web"]["running"] and vms["web"]["pid"] == 42
    assert vms["off"]["pid"] is None


def test_engine_status_without_engine():
    with client(FakePrim(loadable=False)) as c:
        assert c.get("/api/engine").json()["connected"] is False
        assert c.get("/api/engine/vms").status_code == 503


def test_field_carries_type_names(c):
    f = c.get("/api/vms/web/fields", params={"type": "task_struct", "path": "mm", "addr": hex(KTEXT)}).json()
    assert (f["type_name"], f["ref_name"], f["value"]) == ("ptr <anon>", "struct mm_struct", hex(KTEXT + 0x40))
    assert c.get("/api/vms/web/fields", params={"type": "nope", "path": "x"}).status_code == 502


def test_tasks_keep_guest_strings_verbatim(c):
    assert c.get("/api/vms/web/tasks").json() == [
        {"addr": hex(KTEXT + 0x2000), "pid": 1, "tgid": 1, "comm": "<script>systemd"}]


def test_guest_pages(c):
    page = c.get("/guests")
    assert page.status_code == 200 and 'href="/guests/web"' in page.text and "New guest" in page.text
    detail = c.get("/guests/web")
    assert detail.status_code == 200 and 'id="mem-form"' in detail.text and 'id="write-form"' not in detail.text
    assert c.get("/guests/off").status_code == 200
    assert c.get("/guests/nope").status_code == 404


def test_write_controls_only_when_allowed(prim):
    with client(prim, allow_writes=True) as c:
        assert 'id="write-form"' in c.get("/guests/web").text


def test_guest_pages_without_engine():
    with client(FakePrim(loadable=False)) as c:
        for path in ("/guests", "/guests/web"):
            r = c.get(path)
            assert r.status_code == 200 and "No introspection engine is running" in r.text


def test_snapshot_carries_helpers_attach_and_loader(c):
    rootkit = c.get("/api/vms/web/snapshot").json()["programs"][2]
    assert rootkit["helpers"] == ["bpf_probe_read_user", "bpf_probe_write_user"]
    assert rootkit["attach_points"] == [{"kind": "tracepoint", "target": "syscalls:sys_exit_getdents64", "attached_at": None}]
    assert (rootkit["loader_uid"], rootkit["loader_pid"], rootkit["loader_comm"]) == (0, 6612, "pidhide")


def test_scan_flags_a_getdents_rootkit(c):
    rules = {(d["rule"], d["prog_id"]) for d in c.post("/api/vms/web/scan").json()["detections"]}
    assert rules == {("probe_write_user", 111), ("getdents_hook", 111)}
