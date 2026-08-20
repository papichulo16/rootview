"""Build the standalone static project page into ../../site/.

The site published for the course is a plain HTML page with no server behind
it: identity, deliverables, project summary, tools, challenges and milestones.
It is generated from the same ``rootview_web/deliverables.py`` that drives the
running application, so publishing a document stays a one-line edit in one file
instead of two that can drift apart.

Run it from the ``web/`` directory:

    .venv/bin/python tools/build_static_site.py

Output (all of it safe to commit and serve from GitHub Pages):

    site/index.html
    site/static/css/*.css
    site/static/docs/*        (whatever you dropped in rootview_web/static/docs)
    site/.nojekyll

The generated HTML is ordinary readable markup with no framework, so it can
also be hand-edited afterwards if you would rather not re-run the build. Just
remember that the next build overwrites it.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

# Allow running as a plain script from the web/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rootview_web import deliverables  # noqa: E402
from rootview_web.templating import STATIC_DIR, templates  # noqa: E402

WEB_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = WEB_DIR.parent / "site"

#: Subdirectories of the app's static/ that the standalone page needs. The
#: JavaScript is deliberately excluded: the static page holds no event stream.
STATIC_SUBDIRS = ("css", "docs")


def static_url(name: str = "static", path: str = "") -> str:
    """Stand-in for Starlette's ``url_for`` inside the templates.

    The running app serves assets from an absolute ``/static/...`` path. A page
    opened from a subdirectory on GitHub Pages needs those relative, so this
    returns ``static/css/app.css`` rather than ``/static/css/app.css``.
    """
    return "static/" + path.lstrip("/")


def render_page() -> str:
    """Render landing.html with the server-dependent parts switched off."""
    template = templates.env.get_template("landing.html")
    return template.render(
        url_for=static_url,
        static_build=True,
        project_name=deliverables.PROJECT_NAME,
        team=deliverables.TEAM,
        advisor=deliverables.ADVISOR,
        semesters=deliverables.SEMESTERS,
        tools=deliverables.TOOLS,
        challenges=deliverables.CHALLENGES,
        # Present so the template's guards evaluate; none of it is rendered
        # while static_build is true.
        active="home",
        live=False,
        connected=False,
        running_count=0,
        vms=[],
        settings=None,
    )


def rewrite_absolute_asset_links(html: str) -> str:
    """Make any ``/static/...`` link in the page content relative.

    Deliverable urls pointing at a local file (``/static/docs/plan.pdf``) are
    written for the running server. External urls are left alone.
    """
    return html.replace('href="/static/', 'href="static/')


def copy_assets() -> list[Path]:
    """Copy the stylesheets and any published documents into the output."""
    copied = []
    for subdir in STATIC_SUBDIRS:
        source = STATIC_DIR / subdir
        if not source.is_dir():
            continue
        destination = OUTPUT_DIR / "static" / subdir
        shutil.rmtree(destination, ignore_errors=True)
        shutil.copytree(source, destination)
        copied.extend(sorted(p for p in destination.rglob("*") if p.is_file()))
    return copied


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    html = rewrite_absolute_asset_links(render_page())
    index = OUTPUT_DIR / "index.html"
    index.write_text(html, encoding="utf-8")

    assets = copy_assets()

    # Stops GitHub Pages from running the output through Jekyll, which would
    # otherwise ignore any file or directory starting with an underscore.
    (OUTPUT_DIR / ".nojekyll").write_text("", encoding="utf-8")

    print(f"wrote {index.relative_to(OUTPUT_DIR.parent)} ({len(html):,} bytes)")
    for asset in assets:
        print(f"      {asset.relative_to(OUTPUT_DIR.parent)}")

    unpublished = [
        f"{row['milestone']}: {doc['label']}"
        for semester in deliverables.SEMESTERS
        for row in semester["rows"]
        for doc in row["documents"]
        if not doc["url"]
    ]
    if unpublished:
        print(f"\n{len(unpublished)} deliverable(s) still without a link:")
        for item in unpublished:
            print(f"      {item}")


if __name__ == "__main__":
    main()
