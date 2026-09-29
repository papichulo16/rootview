#!/usr/bin/env python3
"""Boots a kernel under plain qemu/kvm and captures one prof test fixture.

Guest side (over the serial console): /proc/kallsyms with kptr_restrict=0,
/sys/kernel/btf/vmlinux, uname -r, /proc/cmdline, MSR_LSTAR, and the PTI
status. Host side (qemu monitor): a live read of linux_banner, the paused
vcpu's registers, and a pmemsave of all guest ram taken in the same pause.

The guest needs a busybox root shell on ttyS0 (--login root for the alpine
iso's getty) and virtio_blk; the fixture files are tarred onto a scratch
virtio disk rather than pushed through the serial line.

    collect.py --kernel vmlinuz --initrd initrd [--iso alpine.iso] \\
        [--login root | --wait-for READY] [--config host-config] [--append 'pti=on'] [--pause-in user] [--out tests/fixtures]

The fixture lands in <out>/<uname>_<kaslr|nokaslr>_<pti|nopti>/. mem.raw and
mem.raw.zst are gitignored - publish mem.raw.zst as a release asset.
"""
import argparse, gzip, os, re, shutil, socket, subprocess, sys, tarfile, tempfile, time

SYMS = ["linux_banner", "init_top_pgt", "init_task", "prog_idr", "sys_call_table",
        "entry_SYSCALL_64", "__start_BTF", "__stop_BTF", "phys_base"]
CONFIG_RE = r"CONFIG_(KALLSYMS|DEBUG_INFO_BTF|(MITIGATION_)?PAGE_TABLE_ISOLATION|RANDOMIZE_BASE|X86_5LEVEL|RELOCATABLE|PGTABLE_LEVELS)[_A-Z]*="

GUEST = f"""
echo 0 > /proc/sys/kernel/kptr_restrict
mkdir -p /tmp/fx && cd /tmp/fx
cat /proc/kallsyms > kallsyms
cat /sys/kernel/btf/vmlinux > vmlinux.btf
uname -r > uname
cat /proc/cmdline > cmdline
cat /sys/devices/system/cpu/vulnerabilities/meltdown > meltdown
dmesg | grep -i 'page tables isolation' > pti
(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) /media/*/boot/config-$(uname -r) 2>/dev/null) | grep -E '{CONFIG_RE}' > config
for s in {' '.join(SYMS)}; do grep -E " $s\\$" kallsyms || echo "MISSING $s"; done > symcheck
modprobe msr 2>/dev/null || insmod /lib/msr.ko 2>/dev/null
dd if=/dev/cpu/0/msr bs=8 count=1 skip=$((0xC0000082)) iflag=skip_bytes 2>/dev/null | od -An -tx8 | tr -d ' ' > lstar
cd /tmp && tar c fx > /dev/vda && sync
"""


class Vm:
    def __init__(self, a, work):
        self.ser_path, self.mon_path = f"{work}/s", f"{work}/m"
        self.disk = f"{work}/out.img"
        with open(self.disk, "wb") as f:
            f.truncate(64 << 20)
        cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", str(a.mem), "-smp", "1",
               "-kernel", a.kernel, "-initrd", a.initrd,
               "-append", f"{a.base_append} console=ttyS0,115200 {a.append}".strip(),
               "-drive", f"file={self.disk},format=raw,if=virtio",
               "-display", "none", "-net", "none",
               "-serial", f"unix:{self.ser_path},server=on,wait=off",
               "-monitor", f"unix:{self.mon_path},server=on,wait=off"]
        if a.iso:
            cmd += ["-drive", f"file={a.iso},media=cdrom,readonly=on"]
        self.cmdline = cmd
        self.proc = subprocess.Popen(cmd)
        self.ser = self._connect(self.ser_path)
        self.log = open(f"{work}/serial.log", "wb")
        self.buf = b""

    @staticmethod
    def _connect(path):
        for _ in range(100):
            try:
                s = socket.socket(socket.AF_UNIX)
                s.connect(path)
                return s
            except OSError:
                time.sleep(0.1)
        sys.exit(f"could not connect to {path}")

    def expect(self, pat, timeout=300):
        self.ser.settimeout(1)
        end = time.time() + timeout
        while time.time() < end:
            i = self.buf.find(pat)
            if i >= 0:
                self.buf = self.buf[i + len(pat):]
                return
            try:
                d = self.ser.recv(65536)
            except socket.timeout:
                continue
            self.log.write(d)
            self.log.flush()
            self.buf += d
        sys.exit(f"timed out waiting for {pat!r} (see serial.log)")

    def sh(self, cmd, timeout=300):
        tag = os.urandom(4).hex()
        # the quotes keep the echoed command line from matching the marker
        self.ser.sendall(f"{cmd}; echo DO''NE_{tag}\n".encode())
        self.expect(f"DONE_{tag}".encode(), timeout)

    def hmp(self, cmd):
        s = self._connect(self.mon_path)
        s.settimeout(1.5)
        time.sleep(0.2)
        try:
            s.recv(65536)  # banner + prompt
        except socket.timeout:
            pass
        s.sendall(cmd.encode() + b"\n")
        out = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        s.close()
        # drop the echoed command line and trailing prompt
        text = out.decode(errors="replace").replace("\r", "")
        return text.split("\n", 1)[-1].rsplit("(qemu)", 1)[0]


def cpl(regs):
    return int(re.search(r"CPL=(\d)", regs).group(1))


def reg(regs, name):
    return int(re.search(rf"\b{name}=([0-9a-f]+)", regs).group(1), 16)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--initrd", required=True)
    ap.add_argument("--iso", help="attached as a cdrom (the alpine initramfs mounts modloop from it)")
    ap.add_argument("--login", help="user to log in as at a getty prompt; omit if the initrd drops to a shell")
    ap.add_argument("--wait-for", help="serial output that means the shell is up, for initrds without a getty")
    ap.add_argument("--config", help="host copy of the kernel config, if the guest has neither /proc/config.gz nor /boot/config-*")
    ap.add_argument("--base-append", default="", help="kernel args the image itself needs")
    ap.add_argument("--append", default="", help="the fixture's variant flags, e.g. 'pti=on' or 'nokaslr'")
    ap.add_argument("--mem", type=int, default=1024, help="MiB; keep <= 2048 so ram is one contiguous range")
    ap.add_argument("--pause-in", choices=["any", "user"], default="any",
                    help="'user' spins a userspace loop and re-pauses until CPL=3, to catch a KPTI user PGD")
    ap.add_argument("--force", action="store_true", help="replace an existing fixture of the same name")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__))))
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="rvfx")
    vm = Vm(a, work)
    ok = False
    try:
        if a.wait_for:
            vm.expect(a.wait_for.encode())
        if a.login:
            vm.expect(b"login: ")
            vm.ser.sendall(a.login.encode() + b"\n")
        time.sleep(3)
        vm.sh("stty -echo")
        for line in GUEST.strip().splitlines():
            vm.sh(line)

        with tarfile.open(vm.disk) as t:
            t.extractall(work, filter="data")
        fx = f"{work}/fx"
        uname = open(f"{fx}/uname").read().strip()
        cmdline = open(f"{fx}/cmdline").read()
        # the meltdown file reports the cpu, not whether pti=on forced it
        pti = open(f"{fx}/pti").read()
        name = f"{uname}_{'nokaslr' if 'nokaslr' in cmdline.split() else 'kaslr'}_{'pti' if 'enabled' in pti else 'nopti'}"
        syms = {l.split()[2]: int(l.split()[0], 16) for l in open(f"{fx}/symcheck") if len(l.split()) == 3}
        missing = [l.split()[1] for l in open(f"{fx}/symcheck") if l.startswith("MISSING")]

        # live read of linux_banner through the vcpu's own translation. under
        # KPTI a vcpu paused in userspace can't see it, so retry until it can.
        live = None
        for _ in range(50):
            vm.hmp("stop")
            out = vm.hmp(f"x/256xb 0x{syms['linux_banner']:x}")
            vm.hmp("cont")
            if "Cannot access" not in out:
                live = bytes(int(x, 16) for line in out.splitlines() for x in re.findall(r"\b0x([0-9a-f]{2})\b", line.split(":", 1)[-1]))
                break
            time.sleep(0.2)
        if not live:
            sys.exit("could not read linux_banner through the vcpu's CR3")
        live = live.split(b"\0", 1)[0]

        if a.pause_in == "user":
            vm.ser.sendall(b"while :; do :; done &\n")
            time.sleep(1)
        for _ in range(200):
            vm.hmp("stop")
            regs = vm.hmp("info registers")
            if a.pause_in == "any" or cpl(regs) == 3:
                break
            vm.hmp("cont")
            time.sleep(0.05)
        else:
            sys.exit("never caught the vcpu in userspace")

        dest = os.path.join(a.out, name)
        if os.path.exists(dest) and not a.force:
            sys.exit(f"{dest} already exists (--force to replace it)")
        os.makedirs(dest, exist_ok=True)
        dump = os.path.abspath(f"{dest}/mem.raw")
        vm.hmp(f'pmemsave 0 0x{a.mem << 20:x} "{dump}"')
        for _ in range(120):
            if os.path.exists(dump) and os.path.getsize(dump) == a.mem << 20:
                break
            time.sleep(0.5)
        vm.hmp("quit")
        vm.proc.wait(timeout=30)

        lstar = int(open(f"{fx}/lstar").read().strip() or "0", 16)
        for src, dst in (("kallsyms", "kallsyms.gz"), ("vmlinux.btf", "vmlinux.btf.gz")):
            with open(f"{fx}/{src}", "rb") as i, gzip.open(f"{dest}/{dst}", "wb", 9) as o:
                shutil.copyfileobj(i, o)
        for f in ("config", "cmdline", "uname", "symcheck", "meltdown", "pti"):
            shutil.copy(f"{fx}/{f}", f"{dest}/{f}")
        if a.config and not os.path.getsize(f"{dest}/config"):
            with open(f"{dest}/config", "w") as o:
                o.writelines(l for l in open(a.config) if re.match(CONFIG_RE, l))
        open(f"{dest}/regs.txt", "w").write(regs)
        open(f"{dest}/regs", "w").write(
            f"cr3=0x{reg(regs, 'CR3'):x}\ncr4=0x{reg(regs, 'CR4'):x}\nrip=0x{reg(regs, 'RIP'):x}\n"
            f"cpl={cpl(regs)}\nefer=0x{reg(regs, 'EFER'):x}\nlstar=0x{lstar:x}\n")
        open(f"{dest}/live_banner.bin", "wb").write(live)
        qcmd = [c.replace(work, "$WORK") for c in vm.cmdline]
        open(f"{dest}/qemu.cmd", "w").write(" ".join(qcmd) + "\n")
        subprocess.run(["zstd", "-q", "-f", "-T0", "-10", dump, "-o", f"{dump}.zst"], check=True)

        print(f"fixture {name}")
        print(f"  cr3=0x{reg(regs, 'CR3'):x} cpl={cpl(regs)} lstar=0x{lstar:x}")
        print(f"  {live.decode(errors='replace').strip()}")
        if missing:
            print(f"  MISSING symbols: {' '.join(missing)}")
        ok = True
    finally:
        if vm.proc.poll() is None:
            vm.proc.kill()
        if ok:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"left {work} (serial.log) for debugging", file=sys.stderr)


if __name__ == "__main__":
    main()
