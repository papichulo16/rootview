#!/bin/sh
# builds librootview.so and installs the rootview package into .venv
set -e
cd "$(dirname "$0")"

python3 -c "import ensurepip" 2>/dev/null || sudo apt-get install -y python3-venv
make lib
python3 -m venv .venv
.venv/bin/pip install -q -e .

echo "done: . .venv/bin/activate"
