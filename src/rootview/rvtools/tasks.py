"""task_structs, reached through each structure the kernel keeps them in.

Each source returns task_struct addresses; ``sources()`` runs them all and
says which reached which task. What a difference means is the caller's call
(a thread is never on the task list; only running tasks are on runqueues).
"""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprimitives import Guest, RootviewError
from rootview.rvtools.common import Layout, is_kernel_va, read_u64

PF_KTHREAD = 0x00200000

#: the source names sources() uses, in the order it runs them
SOURCES = ("task_list", "pid_idr", "runqueue", "children", "threads")


@dataclass(frozen=True)
class TaskInfo:
    addr: int
    pid: int
    tgid: int
    comm: str
    real_parent: int
    mm: int
    flags: int  # PF_*

    @property
    def kthread(self) -> bool:
        return bool(self.flags & PF_KTHREAD)

    @property
    def leader(self) -> bool:
        return self.pid == self.tgid


class Tasks:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.layout = Layout(g, "task_struct", "tasks", "children", "sibling", "thread_node", "signal",
                             "pid_links", "pid", "tgid", "comm", "real_parent", "mm", "flags")
        self.off_thread_head = g.field("signal_struct", "thread_head").offset

    def task_list(self) -> list[int]:
        """init_task.tasks, init_task included: thread group leaders."""
        init, off = self.g.info().init_task, self.layout.off("tasks")
        return [init] + self.g.list_off(init + off, off)

    def pid_idr(self) -> list[int]:
        """init_pid_ns.idr -> pid->tasks[PIDTYPE_PID]: every task with a pid (what /proc lists)."""
        g = self.g
        idr = g.sym("init_pid_ns") + g.field("pid_namespace", "idr").offset
        tasks_off = g.field("pid", "tasks").offset  # tasks[PIDTYPE_PID]
        links = self.layout.off("pid_links")  # pid_links[PIDTYPE_PID]
        out = []
        for _, pid in g.idr(idr):
            out += g.hlist_off(pid + tasks_off, links, max=16)
        return out

    def runqueues(self) -> list[int]:
        """Each cpu's rq->curr and rq->idle: whatever is running."""
        g = self.g
        curr, idle = g.field("rq", "curr").offset, g.field("rq", "idle").offset
        out = []
        for cpu in range(g.nr_cpus()):
            rq = g.percpu_addr("runqueues", cpu)
            out += [t for t in (read_u64(g, rq + curr), read_u64(g, rq + idle)) if t]
        return out

    def children(self, task: int) -> list[int]:
        """task->children."""
        return self.g.list_off(task + self.layout.off("children"), self.layout.off("sibling"))

    def threads(self, task: int) -> list[int]:
        """Every thread in task's group: signal->thread_head."""
        sig = read_u64(self.g, task + self.layout.off("signal"))
        if not is_kernel_va(sig):
            raise RootviewError(f"task {task:#x}: signal is {sig:#x}")
        return self.g.list_off(sig + self.off_thread_head, self.layout.off("thread_node"))

    def sources(self) -> tuple[dict[int, set[str]], dict[str, str]]:
        """Every source, in one snapshot: task -> the sources that reached it,
        and source -> why it failed. children and threads are followed from
        every task found until nothing new turns up."""
        found: dict[int, set[str]] = {}
        errors: dict[str, str] = {}

        def add(addrs, source):
            for a in addrs:
                found.setdefault(a, set()).add(source)

        with self.g.snapshot():
            for name, fn in (("task_list", self.task_list), ("pid_idr", self.pid_idr),
                             ("runqueue", self.runqueues)):
                try:
                    add(fn(), name)
                except RootviewError as e:
                    errors[name] = str(e)
            done: set[int] = set()
            while todo := [a for a in found if a not in done]:
                for task in todo:
                    done.add(task)
                    for name, fn in (("children", self.children), ("threads", self.threads)):
                        try:
                            add(fn(task), name)
                        except RootviewError as e:
                            errors.setdefault(name, f"task {task:#x}: {e}")
        return found, errors

    def info(self, addr: int) -> TaskInfo:
        lo = self.layout
        buf = lo.read(self.g, addr)
        return TaskInfo(addr, lo.get(buf, "pid"), lo.get(buf, "tgid"), lo.get(buf, "comm"),
                        lo.get(buf, "real_parent"), lo.get(buf, "mm"), lo.get(buf, "flags"))
