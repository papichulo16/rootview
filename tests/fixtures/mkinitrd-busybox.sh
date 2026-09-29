#!/usr/bin/env bash
# builds the minimal initrd collect.py boots non-alpine kernels with: a static
# busybox, that kernel's virtio_blk.ko and msr.ko, and an /init that prints
# RVREADY and keeps a root shell on ttyS0 (collect.py --wait-for RVREADY).
#
#   mkinitrd-busybox.sh <busybox.static> <lib/modules/<ver>/kernel dir> <out.gz>
#
# busybox.static: alpine's busybox-static apk, bin/busybox.static.
# modules: the kernel's modules package (ubuntu: linux-modules-<ver>_amd64.deb).
# if virtio_blk or msr are built in (=y), their .ko won't exist - that's fine.
set -euo pipefail

bb="$1" moddir="$2" out="$(realpath -m "$3")"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root"/{bin,lib,proc,sys,dev,tmp}
cp "$bb" "$root/bin/busybox"
for ko in drivers/block/virtio_blk.ko arch/x86/kernel/msr.ko; do
    [ -e "$moddir/$ko" ] && cp "$moddir/$ko" "$root/lib/"
done

cat > "$root/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
[ -e /lib/virtio_blk.ko ] && insmod /lib/virtio_blk.ko
echo RVREADY
while :; do setsid sh -c 'exec sh </dev/ttyS0 >/dev/ttyS0 2>&1'; done
EOF
chmod +x "$root/init"

(cd "$root" && find . | cpio -o -H newc --quiet | gzip -9) > "$out"
echo "wrote $out"
