# Building

```sh
make            # rv
make lib        # librootview.so (bind/Makefile)
pip install -e .
```

Needs libvmi and libvirt, and a host running the KVMI kernel (kvmi-vm).

Attaching needs a guest started with kvmi: `./rv vm start <vm>`, then wait ~90s.

`rv kvmi attach` failing with `init_error 2` right after boot is KVMI
connection timing: retry after a few seconds.

Hook events (`poll`/`events`, and so `MemWatch`) need the host to deliver
KVMI events. The current AMD kvmi-vm delivers none.
