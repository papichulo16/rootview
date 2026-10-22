# Python API

```sh
make lib            # builds librootview.so at the repo root
pip install -e .    # the rootview package (no dependencies)
```

```python
from rootview import Guest

with Guest("myvm") as g:
    print(g.read_field("task_struct", "comm", g.sym("init_task")).value)  # swapper/0
```

- [rvprim](rvprim.md): the VMI primitives.
- [rvtools](rvtools.md): tooling on top of them.
- [ebpf](ebpf.md): rvtools' eBPF programs, maps and attachments.

Every failure raises `rootview.RootviewError`. Calls are thread-safe (one lock).
