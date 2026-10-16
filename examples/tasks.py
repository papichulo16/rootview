"""Every task_struct and which structures reach it.

    python examples/tasks.py [vm]
"""

import sys

from rootview.rvtools import Tasks, attach
from rootview.rvtools.tasks import SOURCES

with attach(sys.argv[1] if len(sys.argv) > 1 else None) as g:
    tasks = Tasks(g)
    found, errors = tasks.sources()
    infos = {a: tasks.info(a) for a in found}

print(f"{'PID':>7} {'TGID':>7} K {'COMM':<16} {'SOURCES':<44} TASK")
for a, srcs in sorted(found.items(), key=lambda kv: infos[kv[0]].pid):
    t = infos[a]
    marks = " ".join(s if s in srcs else "-" * len(s) for s in SOURCES)
    print(f"{t.pid:>7} {t.tgid:>7} {'k' if t.kthread else ' '} {t.comm:<16} {marks:<44} {a:#x}")
print(f"\n{len(found)} tasks: " + ", ".join(f"{s}={sum(s in v for v in found.values())}" for s in SOURCES))
for src, err in errors.items():
    print(f"{src} failed: {err}")
