#!/usr/bin/env bash
#
# Start the RootView web server, building the virtualenv first if it is not
# there yet.
#
#   ./run.sh             serve on http://127.0.0.1:8000; Ctrl-C to stop
#   ./run.sh --reload    same, but restart when a .py file changes
#
# Configuration is read from the environment, all of it optional:
#
#   ROOTVIEW_PORT=8080 ./run.sh
#   ROOTVIEW_BACKEND=libvmi ./run.sh
#   ROOTVIEW_SCAN_INTERVAL=2 ./run.sh
#
# Safe to run every time. The venv is only built when it is missing or when
# pyproject.toml has changed since the last install, so the ordinary case is
# just the server starting.

set -euo pipefail

# Work from the directory holding this script, so it does not matter where it
# was called from.
cd "$(dirname "${BASH_SOURCE[0]}")"

VENV=".venv"
STAMP="$VENV/.install-stamp"

die() { printf 'run.sh: %s\n' "$1" >&2; exit 1; }
note() { printf 'run.sh: %s\n' "$1"; }

command -v python3 >/dev/null 2>&1 || die "python3 was not found on PATH."

# pyproject.toml requires >= 3.10. Checking it here turns what would otherwise
# be an opaque pip resolution failure into a sentence saying what to install.
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die \
  "Python 3.10 or newer is required; python3 is $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')."

# A venv whose interpreter has gone missing is worse than no venv at all: it is
# what a moved or copied checkout leaves behind, and every command run against
# it fails confusingly. Rebuild rather than try to use it.
if [[ -d "$VENV" && ! -x "$VENV/bin/python" ]]; then
  note "$VENV has no interpreter (moved or copied checkout?); rebuilding it."
  rm -rf "$VENV"
fi

if [[ ! -d "$VENV" ]]; then
  note "creating $VENV"
  python3 -m venv "$VENV"
fi

# Reinstall when the venv is new or a dependency has changed, so picking up a
# new requirement never depends on anyone remembering to.
if [[ ! -f "$STAMP" || pyproject.toml -nt "$STAMP" ]]; then
  note "installing dependencies (this takes a moment the first time)"
  "$VENV/bin/pip" install --quiet --disable-pip-version-check --editable ".[dev]"
  touch "$STAMP"
fi

# exec so the server replaces this shell. Ctrl-C then reaches uvicorn directly
# and its shutdown runs -- the scanner loop is cancelled and the backend is
# closed -- instead of the signal killing the wrapper and orphaning the server.
if [[ "${1:-}" == "--reload" ]]; then
  exec "$VENV/bin/uvicorn" rootview_web.app:app --reload \
    --host "${ROOTVIEW_HOST:-127.0.0.1}" \
    --port "${ROOTVIEW_PORT:-8000}"
fi

exec "$VENV/bin/rootview-web"
