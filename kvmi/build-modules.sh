#!/bin/sh
# Builds kvm.ko, kvm-amd.ko and kvm-intel.ko with introspection for the
# running Ubuntu kernel and installs them to /lib/modules/<release>/updates.
set -e
here=$(cd "$(dirname "$0")" && pwd)

krel=$(uname -r)
base=${krel%%-*}
abi=${krel#"$base"}
pkg=linux-source-$base
work=${KVMI_WORK:-$HOME/.cache/rootview-kvmi}/$krel

sudo apt-get install -y "$pkg" "linux-headers-$krel" build-essential flex bison bc \
	libelf-dev libssl-dev libdw-dev dwarves

srcver=$(dpkg-query -W -f='${Version}' "$pkg")
case "$srcver" in
"$base${abi%-*}".*) ;;
*) echo "$pkg is $srcver, which doesn't match the running kernel $krel" >&2; exit 1 ;;
esac

rm -rf "$work"
mkdir -p "$work/build" "$work/out/arch/x86/kvm" "$work/out/virt/kvm"
tar xf "/usr/src/$pkg/$pkg.tar.bz2" -C "$work"
mv "$work/$pkg" "$work/linux"

cd "$work/linux"
for p in "$here"/patches/linux/*.patch; do
	patch -p1 -s --no-backup-if-mismatch < "$p"
done

# Ubuntu names the release after the series base even when the tree's
# SUBLEVEL has moved on (7.3.0-11 is 7.3.1 upstream)
make="make -s O=$work/build KERNELVERSION=$base LOCALVERSION=$abi"
cp "/boot/config-$krel" "$work/build/.config"
$make olddefconfig
$make -j"$(nproc)" modules_prepare
[ "$($make kernelrelease)" = "$krel" ] || { echo "kernel release mismatch" >&2; exit 1; }

# vmlinux symbols only; the KVM modules export their own
awk -F'\t' '$3 !~ /^arch\/x86\/kvm\//' "/usr/src/linux-headers-$krel/Module.symvers" \
	> "$work/build/Module.symvers"

$make -j"$(nproc)" M="$work/linux/arch/x86/kvm" MO="$work/out/arch/x86/kvm" \
	CONFIG_KVM_INTROSPECTION=y KCFLAGS=-DCONFIG_KVM_INTROSPECTION=1 modules

sudo install -D -m 644 -t "/lib/modules/$krel/updates/kvmi" "$work"/out/arch/x86/kvm/kvm*.ko
sudo depmod -a "$krel"
echo "installed to /lib/modules/$krel/updates/kvmi (run ./load-modules.sh or reboot)"
