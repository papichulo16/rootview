# Adding a primitive

1. **C**: implement it in the module that owns it (`kern/`, `kvmi/vmi/`, `kvmi/hook/`), declared in `src/intf/`.
2. **bind**: add `API int rv_<name>(rv_handle_t *h, ..., char *err, size_t err_len)` to `bind/rootview.c` and `rootview.h`. Return 0, or -1 with err set.
3. **Python**: add its ctypes signature to `sigs` in `rvprim._load`, and a `Guest` method that calls it through `_call`.
4. **Docs**: one row in `docs/python/rvprim.md`.

Keep primitives generic. Anything that decides what is malicious belongs above rvtools.
