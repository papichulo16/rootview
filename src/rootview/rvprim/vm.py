from __future__ import annotations

import ctypes as c
import os
import socket
from dataclasses import asdict, fields

from rootview.rvprim import _structs as s
from rootview.rvprim._lib import RootviewError, call, declare, fill, lib, lock, text
from rootview.rvprim.types import Vm, VmConfig

_err = (c.c_char_p, c.c_size_t)
_name = (c.c_char_p, *_err)
declare({
    "rv_set_base": (None, (c.c_char_p,)),
    "rv_vm_list": (c.c_int, (c.POINTER(s.Vm), c.c_size_t, c.POINTER(c.c_size_t), *_err)),
    "rv_vm_inspect": (c.c_int, (c.c_char_p, c.POINTER(s.Vm), *_err)),
    "rv_vm_defaults": (None, (c.c_char_p, c.POINTER(s.VmConfig))),
    "rv_vm_config_file": (c.c_int, (c.c_char_p, c.POINTER(s.VmConfig), *_err)),
    "rv_vm_create": (c.c_int, (c.POINTER(s.VmConfig), *_err)),
    "rv_vm_start": (c.c_int, _name),
    "rv_vm_stop": (c.c_int, _name),
    "rv_vm_restart": (c.c_int, _name),
    "rv_vm_destroy": (c.c_int, (c.c_char_p, c.c_int, *_err)),
})

_CONFIG_FIELDS = {f.name for f in fields(VmConfig)}


def _config(raw: s.VmConfig) -> VmConfig:
    return VmConfig(
        name=text(raw.name),
        memory_mb=raw.memory_mb,
        cpus=raw.cpus,
        disk_image=text(raw.disk_image),
        cdrom=text(raw.cdrom),
        network=text(raw.network),
        display=text(raw.display),
        kvm=bool(raw.use_kvm),
        kvmi_enabled=bool(raw.kvmi_enabled),
        extra_args=text(raw.extra_args),
    )


def _raw_config(cfg: VmConfig) -> s.VmConfig:
    raw = s.VmConfig()
    for key, value in asdict(cfg).items():
        target = {"kvm": "use_kvm"}.get(key, key)
        setattr(raw, target, value.encode() if isinstance(value, str) else int(value))
    return raw


def _vm(raw: s.Vm) -> Vm:
    running = bool(raw.running)
    return Vm(
        name=text(raw.config.name),
        config=_config(raw.config),
        running=running,
        kvmi=bool(raw.kvmi),
        pid=raw.pid if running else None,
        started_at=raw.started_at if running else None,
        qmp_socket=text(raw.qmp_socket),
        monitor_socket=text(raw.monitor_socket),
        kvmi_socket=text(raw.kvmi_socket),
        log_path=text(raw.log_path),
    )


def set_base(dir: str | os.PathLike) -> None:
    fn = lib().rv_set_base
    with lock:
        fn(str(dir).encode())


def list_vms() -> list[Vm]:
    return [_vm(v) for v in fill("rv_vm_list", s.Vm)]


def inspect_vm(name: str) -> Vm:
    raw = s.Vm()
    call("rv_vm_inspect", name.encode(), c.byref(raw))
    return _vm(raw)


def vm_defaults(name: str) -> VmConfig:
    raw = s.VmConfig()
    fn = lib().rv_vm_defaults
    with lock:
        fn(name.encode(), c.byref(raw))
    return _config(raw)


def create_vm(name: str, config_file: str | os.PathLike | None = None, **overrides) -> Vm:
    unknown = set(overrides) - _CONFIG_FIELDS - {"name"}
    if unknown:
        raise TypeError(f"unknown vm settings: {', '.join(sorted(unknown))}")
    raw = _raw_config(vm_defaults(name))
    if config_file is not None:
        call("rv_vm_config_file", str(config_file).encode(), c.byref(raw))
    cfg = _config(raw)
    raw = _raw_config(VmConfig(**{**asdict(cfg), **overrides, "name": name}))
    call("rv_vm_create", c.byref(raw))
    return inspect_vm(name)


def start_vm(name: str) -> None:
    call("rv_vm_start", name.encode())


def stop_vm(name: str) -> None:
    call("rv_vm_stop", name.encode())


def restart_vm(name: str) -> None:
    call("rv_vm_restart", name.encode())


def console(name: str) -> socket.socket:
    vm = inspect_vm(name)
    if not vm.running:
        raise RootviewError(f"vm '{name}' is not running")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(vm.monitor_socket)
    except OSError as e:
        sock.close()
        raise RootviewError(f"failed to connect to monitor socket {vm.monitor_socket}: {e}") from None
    return sock


def destroy_vm(name: str, force: bool = False) -> None:
    call("rv_vm_destroy", name.encode(), int(force))
