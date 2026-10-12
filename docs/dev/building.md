# Building and testing

```sh
make            # rv
make lib        # librootview.so (bind/Makefile)
pip install -e '.[dev]'
```

Needs libvmi and libvirt, and a host running the KVMI kernel (kvmi-vm).

Tests are live: they need a running guest started with kvmi.

```sh
./rv vm start <vm>              # wait until attach works (~90s after boot)
ROOTVIEW_TEST_VM=<vm> pytest    # skips without a guest or librootview.so
```

`rv kvmi attach` failing with `init_error 2` right after boot is KVMI
connection timing: retry after a few seconds.

Hook events (`poll`/`events`, and so `MemWatch`) need the host to deliver
KVMI events. The current AMD kvmi-vm delivers none, so those tests skip.
