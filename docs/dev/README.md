# Developer guide

- [Layout](layout.md): where things live.
- [Building and testing](building.md).
- [Adding a primitive](adding-a-primitive.md): C to Python.

Conventions: C follows the existing style (snake_case, `module_action_target`,
single exit via `goto`, err/err_len out-params). Python modules mirror the
layer they sit in: no detection logic below the detection layer.
