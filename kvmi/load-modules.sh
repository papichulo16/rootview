#!/bin/sh
# Swaps the running KVM modules for the installed introspection build.
# Every VM on this host has to be shut down first.
set -e

sudo modprobe -r kvm_amd kvm_intel kvm 2>/dev/null || true
if grep -q svm /proc/cpuinfo; then
	sudo modprobe kvm_amd
else
	sudo modprobe kvm_intel
fi

modinfo -F filename kvm
echo "introspection: $(cat /sys/module/kvm/parameters/introspection)"
