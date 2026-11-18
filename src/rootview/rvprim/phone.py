"""Android phones over adb: what Rootview("pkvm-vmi", serial) can attach to."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from rootview.rvprim._lib import RootviewError

ADB_TIMEOUT = 10
# where pkvmi-mod's device and CLI are; the CLI path matches PKVMI_ADB_CLI_PATH
PKVMI_DEV = "/dev/pkvmi"
PKVMI_CLI = "/data/local/tmp/pkvmi"


@dataclass(frozen=True)
class Phone:
    serial: str
    state: str  # adb's: device, unauthorized, offline, ...
    model: str
    product: str
    pkvmi: bool  # /dev/pkvmi and the CLI are on it, so pkvm-vmi can attach

    @property
    def connected(self) -> bool:
        return self.state == "device"


def _adb(*args: str) -> str:
    try:
        out = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=ADB_TIMEOUT)
    except FileNotFoundError:
        raise RootviewError("adb is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise RootviewError(f"adb {' '.join(args)} timed out") from None
    if out.returncode != 0:
        raise RootviewError(out.stderr.strip() or f"adb {' '.join(args)} failed")
    return out.stdout


def _pkvmi_ready(serial: str) -> bool:
    try:
        out = _adb("-s", serial, "shell", f"test -e {PKVMI_DEV} && test -x {PKVMI_CLI} && echo ok")
    except RootviewError:
        return False
    return out.strip() == "ok"


def _parse(line: str) -> Phone:
    serial, state, *props = line.split()
    kv = dict(p.split(":", 1) for p in props if ":" in p)
    ready = state == "device" and _pkvmi_ready(serial)
    return Phone(serial, state, kv.get("model", "").replace("_", " "), kv.get("product", ""), ready)


def list_phones() -> list[Phone]:
    """Every device adb sees, connected or not."""
    lines = _adb("devices", "-l").splitlines()[1:]
    return [_parse(line) for line in lines if line.strip() and not line.startswith("*")]


def inspect_phone(serial: str) -> Phone:
    for p in list_phones():
        if p.serial == serial:
            return p
    raise RootviewError(f"no phone {serial!r} on adb")
