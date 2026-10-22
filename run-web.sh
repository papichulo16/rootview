#!/bin/sh
# builds librootview.so and starts the web server on the libvmi backend
# args pass through to src/ui/dynamic/run.sh (e.g. --reload)
set -e
cd "$(dirname "$0")"

python3 -c "import ensurepip" 2>/dev/null || sudo apt-get install -y python3-venv
make lib
ROOTVIEW_BACKEND="${ROOTVIEW_BACKEND:-libvmi}" exec src/ui/dynamic/run.sh "$@"
