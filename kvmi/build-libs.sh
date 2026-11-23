#!/bin/sh
# Builds libkvmi and LibVMI (with the KVMI fix) into /usr/local.
set -e
here=$(cd "$(dirname "$0")" && pwd)

libkvmi_rev=${LIBKVMI_REV:-bc80de9}
libvmi_rev=${LIBVMI_REV:-82bbee6}
work=${KVMI_WORK:-$HOME/.cache/rootview-kvmi}/libs

sudo apt-get install -y build-essential git autoconf automake libtool cmake pkg-config \
	flex bison libglib2.0-dev libjson-c-dev libyajl-dev libvirt-dev

rm -rf "$work"
mkdir -p "$work"
cd "$work"

git clone -q https://github.com/bitdefender/libkvmi.git
cd libkvmi
git checkout -q "$libkvmi_rev"
./bootstrap
./configure --prefix=/usr/local
make -j"$(nproc)"
sudo make install
cd ..

git clone -q https://github.com/libvmi/libvmi.git
cd libvmi
git checkout -q "$libvmi_rev"
for p in "$here"/patches/libvmi/*.patch; do
	patch -p1 -s --no-backup-if-mismatch < "$p"
done
cmake -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DENABLE_XEN=OFF -DENABLE_KVM=ON \
	-DBUILD_EXAMPLES=OFF
make -C build -j"$(nproc)"
sudo make -C build install

sudo ldconfig
