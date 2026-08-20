# RootView Web

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

## The two front ends

| | What it is | Where it runs |
| --- | --- | --- |
| `dyanmic/` (this folder) | The application: dashboard, introspection view, JSON API | On the KVM host, next to the guest VMs |
| `../static/` | A static project page: identity, deliverables, milestones | Anywhere. No server, publishable to GitHub Pages |

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

