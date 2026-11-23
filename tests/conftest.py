"""Live tests: skipped unless librootview.so loads (``make lib``) and a guest
is up. ``ROOTVIEW_TEST_VM`` names it, otherwise the first running vm with a
kvmi socket is used. Attaching builds the profile, which pauses the guest briefly."""

from __future__ import annotations

import os

import pytest

from rootview import rvprim
from rootview.rvprim import RootviewError


def _guest_name() -> str | None:
    if name := os.environ.get("ROOTVIEW_TEST_VM"):
        return name
    return next((v.name for v in rvprim.list_vms() if v.running and v.kvmi), None)


@pytest.fixture(scope="session")
def guest():
    try:
        rvprim.lib()
    except RootviewError as e:
        pytest.skip(f"librootview.so not loadable: {e}")
    name = _guest_name()
    if name is None:
        pytest.skip("no running kvmi guest (set ROOTVIEW_TEST_VM)")
    with rvprim.Guest(name) as g:
        yield g
