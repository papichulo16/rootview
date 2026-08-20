# RootView — web server

The user-facing half of RootView: a dashboard and introspection GUI over the
KVM/LibVMI engine that inspects a guest's eBPF subsystem from outside the guest.

**There is no introspection backend yet.** The web server, the data contract, the
detection rules and the live event pipeline are all built and tested; the engine
that reads guest memory is a stub waiting to be written. Until it is, the
interface says plainly that it is not reading any guest.

## Run it

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m rootview_web
```

Then open <http://127.0.0.1:8000>.

```sh
.venv/bin/python -m pytest      # 52 tests, no VM required
.venv/bin/uvicorn rootview_web.app:app --reload   # auto-reload while developing
```

## The two front ends

| | What it is | Where it runs |
| --- | --- | --- |
| `web/` (this folder) | The application: dashboard, introspection view, JSON API | On the KVM host, next to the guest VMs |
| `../site/` | A static project page: identity, deliverables, milestones | Anywhere. No server, publishable to GitHub Pages |

Both read their project content from `rootview_web/deliverables.py`, so they
cannot disagree. Rebuild the static page after editing it:

```sh
.venv/bin/python tools/build_static_site.py
```

## Publishing a course deliverable

The landing page opens with the project identity and the deliverables index.
Everything in it comes from **`rootview_web/deliverables.py`** — team members,
advisor, milestones and their documents.

Each document starts with an empty `url` and renders as inert grey text marked
"not published yet". To publish one, drop the file in
`rootview_web/static/docs/` and fill in the url:

```python
{"label": "Plan", "url": "/static/docs/plan.pdf"},
```

It becomes a working link immediately. An external url (Google Doc, GitHub,
anything) works just as well. Nothing outside that file needs to change.

## Writing the backend

> Handing this off to someone who did not build the web server? Give them
> **`BACKEND_GUIDE.txt`** — a standalone, plain-text walkthrough of the whole
> integration, written for someone with no prior context.

This is the next piece of work. Everything is wired up for it already.

1. Open **`rootview_web/backends/libvmi.py`**. It contains `LibVMIBackend` with
   four methods to fill in — `list_vms`, `get_vm`, `snapshot`, `scan` — plus
   `startup`/`shutdown` for resource handling. Each one documents exactly what it
   has to return.
2. Run with `ROOTVIEW_BACKEND=libvmi`. Every page, endpoint and live event is
   then driven by whatever those methods return. Nothing else needs to change.
3. Flip the `connected` property to `True` once introspection genuinely works.

The stub raises `NotImplementedError` rather than returning empty results, on
purpose: an empty list is indistinguishable from "this guest is clean", and the
interface must never imply a clean result it did not establish. While the methods
are unwritten the pages still render, the API returns `501 Not Implemented`, and
the dashboard reports that no backend is connected.

`rootview_web/detection.py` already exists and is backend-agnostic, so `scan` is
mostly:

```python
snap = await self.snapshot(vm_id)
detections = run_rules(snap)
```

## Pages

| Path | What it is |
| --- | --- |
| `/` | Landing page — what the project is, why eBPF rootkits are hard to find, how RootView works. Static; opens no event stream. |
| `/dashboard` | One-line verdict, guest cards, live findings. For a user with no eBPF knowledge. |
| `/introspect` | Raw eBPF program and map tables for one guest. For someone who wants to read the state themselves. |
| `/docs` | Auto-generated OpenAPI docs for the JSON API. |

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness, plus whether a backend is actually connected |
| `GET /api/vms` | Guests available for introspection |
| `GET /api/vms/{id}/snapshot` | Raw eBPF state, no detection logic applied |
| `POST /api/vms/{id}/scan` | Run the detection rules right now |
| `GET /api/detections` | Currently-standing findings (`?vm_id=` to filter) |
| `GET /api/stream` | Live event stream (Server-Sent Events) |

## Configuration

All environment variables, all optional:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTVIEW_BACKEND` | `none` | `none` or `libvmi` |
| `ROOTVIEW_SCAN_INTERVAL` | `5.0` | Seconds between detection passes |
| `ROOTVIEW_HOST` / `ROOTVIEW_PORT` | `127.0.0.1` / `8000` | Bind address |

## How it fits together

```
LibVMI (C, guest memory)  ->  IntrospectionBackend  ->  detection rules  ->  EventBus  ->  SSE  ->  browser
        [not written yet]     backends/libvmi.py        detection.py        events.py         static/js/app.js
```

Three things are worth knowing before changing anything:

**The backend is pull-based.** VMI reads guest memory on demand; nothing in the
guest notifies us when a program is loaded. So `ScannerService` polls every guest
on an interval and publishes what is new. Detection IDs are deterministic
(`vm_id:rule:subject`), which is what lets a standing finding avoid re-alerting
on every pass.

**Detection happens on this side, not in the engine.** The backend's job is to
report *what is there*; `detection.py` decides what is *suspicious*. Rules can be
added and tuned without touching guest memory parsing.

**The interface never claims a clean system it has not verified.** The dashboard
has four states — `alert`, `clear`, `pending`, `unconfigured` — and `clear` is
only reachable after a scan actually completes. This is enforced on the server in
`routers/pages.py:verdict_state` and again in the browser, where only a completed
scan event may set the clear state. A false all-clear is worse than no
information at all, so if you change that logic, keep that property.

## The `visibility` field

This is the core idea. The hypervisor walks guest kernel structures directly, so
it sees ground truth. A guest-side tool like `bpftool` sees only what the
(possibly compromised) kernel chooses to report. Every program and map carries:

- `visible` — hypervisor and guest agree
- `hidden` — hypervisor sees it, guest does not → **something is concealing it**
- `unchecked` — no guest-side comparison was available

`unchecked` is deliberately distinct from `hidden`: RootView must never report a
hidden object when it simply never asked the guest.

## Detection rules

| Rule | Severity | Fires when |
| --- | --- | --- |
| `hidden_program` | critical | Program in kernel memory that the guest does not report |
| `hidden_map` | high | Map in kernel memory that the guest does not report |
| `probe_write_user` | high / medium | Program calls a helper that modifies rather than observes |
| `getdents_hook` | medium | Attached to a syscall used to hide files, processes, or connections |
| `unprivileged_load` | medium | Tracing program loaded by a non-root uid |
| `persistent_pinned` | low | Pinned to bpffs but not attached — staged for later |
| `orphaned_program` | low | Attached and running with no attributable loader |

## No fabricated data

The shipped package contains no sample guests, no example findings and no demo
mode. The only guest data anywhere in the repository is in `tests/conftest.py`,
where it exists so the detection rules and pages can be tested without a VM.

## Known limits

- The event bus is in-memory and single-process. Running more than one web worker
  requires moving it to a shared broker.
- On-demand scans (`POST /api/vms/{id}/scan`) return findings to the caller but do
  not publish to the event stream, so one user clicking "scan now" does not alert
  every other open dashboard.
- `/introspect` reloads the page when the finding count for the viewed guest
  changes, rather than patching rows in place, so the tables always show one
  coherent snapshot.
