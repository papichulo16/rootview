# RootView - static project page

This folder is the **public course page**: project identity, the deliverables
index, the project summary, tools, technical challenges and milestones. It is
plain HTML and CSS with no server, no JavaScript and no backend, so it can be
hosted anywhere and stays reachable whether or not anyone is running the tool.

It is the companion to `../web/`, which is the actual RootView application
(dashboard, introspection view, JSON API). That one needs Python running on the
KVM host next to the guest VMs, so it cannot be published as a public link.

## Do not edit index.html by hand (usually)

This page is **generated**. The content comes from
`../web/rootview_web/deliverables.py`, the same file the application reads, so
the two can never disagree about who is on the team or which documents exist.

To publish a deliverable:

1. Edit `../web/rootview_web/deliverables.py` and fill in the document's `url`.
2. Rebuild:

   ```sh
   cd ../web
   .venv/bin/python tools/build_static_site.py
   ```

3. Commit the changed files in this folder.

The build prints which deliverables are still missing a link, which is a handy
checklist before a milestone is due.

If you would rather hand-edit `index.html` directly, that works too - it is
ordinary readable markup. Just know the next build overwrites it.

## Linking a document

Either kind of url works:

```python
{"label": "Plan", "url": "https://docs.google.com/document/d/..."}   # external
{"label": "Plan", "url": "/static/docs/plan.pdf"}                    # local file
```

For a local file, drop it in `../web/rootview_web/static/docs/` first. The build
copies that folder here and rewrites the link to a relative path, so it works
from any subdirectory on the published site.

A document with an empty url renders as inert grey text marked "not published
yet" rather than a dead link.

## Publishing to GitHub Pages

Once this is in a repository:

**Option A - publish this folder from a branch.** GitHub Pages can serve from
`/docs` on a branch, so rename this folder to `docs/` at the repository root and
choose Settings -> Pages -> Deploy from a branch -> `main` / `/docs`. If you
rename it, update `OUTPUT_DIR` in `../web/tools/build_static_site.py` to match.

**Option B - publish with an Action.** Keep the folder named `site/` and add a
workflow that uploads it as the Pages artifact. This is the better option if you
want the page rebuilt automatically on every push rather than committing
generated files.

Either way the result is a permanent URL that works when your laptop is off.

## What is in here

```
index.html          the page
static/css/         stylesheets, copied from the application
static/docs/        any deliverables you added as local files
.nojekyll           stops GitHub Pages running the output through Jekyll
```
