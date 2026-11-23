#!/bin/sh
# Builds QEMU with the introspection object into /usr/local, where rootview's
# libvirt domains look for it, and lets libvirtd run it under AppArmor.
set -e
here=$(cd "$(dirname "$0")" && pwd)

version=${QEMU_VERSION:-11.0.3}
work=${KVMI_WORK:-$HOME/.cache/rootview-kvmi}/qemu

sudo apt-get install -y build-essential ninja-build meson pkg-config python3-venv \
	python3-pycotap libglib2.0-dev libpixman-1-dev libslirp-dev libfdt-dev \
	libcap-ng-dev libseccomp-dev libzstd-dev flex bison curl xz-utils

rm -rf "$work"
mkdir -p "$work"
curl -fsSL "https://download.qemu.org/qemu-$version.tar.xz" | tar xJ -C "$work"

cd "$work/qemu-$version"
for p in "$here"/patches/qemu/*.patch; do
	patch -p1 -s --no-backup-if-mismatch < "$p"
done

./configure --prefix=/usr/local --target-list=x86_64-softmmu --enable-kvm \
	--enable-slirp --enable-vnc --enable-seccomp --enable-cap-ng \
	--disable-docs --disable-werror
make -j"$(nproc)"
sudo make install

rule='/usr/local/bin/qemu-system-* PUx,'
local=/etc/apparmor.d/local/usr.sbin.libvirtd
if [ -f /etc/apparmor.d/usr.sbin.libvirtd ] && ! sudo grep -qF "$rule" "$local" 2>/dev/null; then
	echo "$rule" | sudo tee -a "$local" >/dev/null
	sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.libvirtd
fi

/usr/local/bin/qemu-system-x86_64 --version | head -1
