# RootView Web

The user-facing half of RootView: a dashboard and introspection GUI over the
KVM/LibVMI engine that inspects a guest's eBPF subsystem from outside the guest.


## Run it

`./run.sh` executes the three commands below for you: it builds the virtualenv
on the first run, then goes straight to serving on every run after that. Ctrl-C
stops it, and `./run.sh --reload` restarts the server whenever you save a `.py`
file.

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m rootview_web
```

Then open <http://127.0.0.1:8000>.

## Where this runs

On the KVM host, next to the guest VMs. LibVMI reads a guest's memory from
outside it, so the server has to sit on the host side of the hypervisor
boundary. Running it inside the guest it is meant to be watching would put it
in the untrusted zone this whole design exists to stay out of.

The public course page (project identity, deliverables, milestones) is a
separate static site in its own repository, published with GitHub Pages.
Nothing in here builds or serves it.

## Publishing a course deliverable

Comes from **`rootview_web/deliverables.py`**
team members, advisor, milestones and their documents.

To publish deliverable, drop the file in
`rootview_web/static/docs/` and fill in the url:

```python
{"label": "Plan", "url": "/static/docs/plan.pdf"},
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

