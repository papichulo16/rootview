"""Guest lifecycle against a scratch store: needs librootview.so, not a guest."""

from __future__ import annotations

import json

import pytest

from rootview import rvprim
from rootview.rvprim import RootviewError
from rootview.rvprim._lib import REPO_ROOT


@pytest.fixture
def store(tmp_path):
    try:
        rvprim.lib()
    except RootviewError as e:
        pytest.skip(f"librootview.so not loadable: {e}")
    rvprim.set_base(tmp_path)
    yield tmp_path
    rvprim.set_base(REPO_ROOT)


def test_create_inspect_destroy(store):
    vm = rvprim.create_vm("t", memory_mb=2048, cpus=2, network="none", display="vnc")
    assert (vm.config.memory_mb, vm.config.cpus, vm.config.network, vm.config.display) == (2048, 2, "none", "vnc")
    assert not vm.running and vm.pid is None
    assert [v.name for v in rvprim.list_vms()] == ["t"]
    rvprim.destroy_vm("t")
    assert rvprim.list_vms() == []


def test_config_file_then_overrides(store):
    cfg = store / "c.json"
    cfg.write_text(json.dumps({"name": "ignored", "memory_mb": 512, "cpus": 4}))
    vm = rvprim.create_vm("t", config_file=cfg, cpus=8)
    assert (vm.name, vm.config.memory_mb, vm.config.cpus) == ("t", 512, 8)


@pytest.mark.parametrize("bad", [{"network": "bogus"}, {"display": "bogus"}])
def test_bad_modes_are_rejected(store, bad):
    with pytest.raises(RootviewError):
        rvprim.create_vm("t", **bad)


def test_unknown_setting_is_a_type_error(store):
    with pytest.raises(TypeError):
        rvprim.create_vm("t", nope=1)


def test_missing_and_stopped_vms_raise(store):
    rvprim.create_vm("t")
    for fn in (rvprim.inspect_vm, rvprim.start_vm, rvprim.stop_vm):
        with pytest.raises(RootviewError):
            fn("missing")
    with pytest.raises(RootviewError):
        rvprim.stop_vm("t")
    with pytest.raises(RootviewError):
        rvprim.Guest("t")
    with pytest.raises(RootviewError):
        rvprim.console("t")
