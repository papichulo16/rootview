# examples

Small scripts that print what `rootview.rvtools` sees in a running guest.
They report facts and make no verdicts.

| Script | Shows |
|---|---|
| `tasks.py` | every task and which structures reach it |
| `modules.py` | every module, which structures reach it, its own symbols (`--carve` to search memory too) |
| `tables.py` | `sys_call_table`, IDT gates and `MSR_LSTAR`, each target placed |
| `ftrace.py` | ftrace records that are enabled or patched |
| `pagehash.py` | `save` per-page hashes of text/rodata, `compare` them later |
| `memwatch.py` | live writes to `sys_call_table` and the IDT |

```sh
make lib && pip install -e .    # librootview.so and the rootview package
python examples/tasks.py [vm]   # vm defaults to the first running kvmi guest
```
