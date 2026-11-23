#!/bin/sh
# Sets up an Ubuntu host as a rootview VMI host: KVMI modules, QEMU,
# libkvmi and LibVMI. Shut down every VM before running it.
set -e
here=$(cd "$(dirname "$0")" && pwd)

sudo apt-get install -y libvirt-daemon-system libvirt-clients qemu-utils

"$here/build-modules.sh"
"$here/build-qemu.sh"
"$here/build-libs.sh"
"$here/load-modules.sh"
