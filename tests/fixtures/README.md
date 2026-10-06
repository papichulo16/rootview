# prof test fixtures

Each directory holds one captured guest, named `<uname -r>_<kaslr|nokaslr>_<pti|nopti>`.
All files come from the same boot, and the ram dump comes from the same pause as `regs`.

| fixture | why it's here |
|---|---|
| `6.18.35-0-lts_kaslr_nopti` | CR3 `0x310f002`: a non-KPTI root on an **odd** page, with PCID bits set. Masking bit 12 lands on junk. Captured by hand during M0. |
| `6.18.35-0-lts_kaslr_pti` | `pti=on`, paused at CPL=3 on the **user PGD** (CR3 `0x1ad3d801`). The kernel root is the even page. |
| `6.18.35-0-lts_nokaslr_nopti` | `nokaslr`: the image sits at the default `0xffffffff81000000`. The image (PDPT[510]) and modules (PDPT[511], from `0xffffffffc0000000`) share the PML4[511] PDPT page. That holds with KASLR too. |
| `5.15.0-198-generic_kaslr_nopti` | Old kallsyms layout (no `kallsyms_seqs_of_names`), from Ubuntu 22.04's GA kernel. Also has an odd-page root. |

## Files

Committed (small, and the ground truth everything gets diffed against):

- `kallsyms.gz`: `/proc/kallsyms` with `kptr_restrict=0`
- `vmlinux.btf.gz`: `/sys/kernel/btf/vmlinux`
- `config`: the relevant `CONFIG_*` lines
- `cmdline`, `uname`: `/proc/cmdline` and `uname -r`
- `symcheck`: the kallsyms lines for the symbols the profiler needs
- `regs`: the paused vcpu's registers as `key=0x...`. `lstar` comes from `/dev/cpu/0/msr` in the guest.
- `regs.txt`: raw `info registers` from the qemu monitor
- `live_banner.bin`: `linux_banner` as read live through the vcpu's own translation (the monitor's `x`), up to the NUL
- `meltdown`, `pti`: the cpu's meltdown status and the dmesg page-table-isolation line. The meltdown file reports the cpu, not whether `pti=on` forced it, so the name comes from `pti`.
- `qemu.cmd`: the exact qemu command line (`$WORK` is collect.py's temp dir)

Not committed (see `.gitignore`):

- `mem.raw`: `pmemsave 0 <ram>` of the whole guest. File offset == guest-physical address (1 GiB guests, so ram is one contiguous range).
- `mem.raw.zst`: the same file compressed. Publish it as a release asset named `<fixture>.mem.raw.zst`.

## Running the dump tests

`make test` always runs the synthetic tests: page tables and `pt_image` (`test_pt`), and kallsyms tables in all three layouts plus corrupted and truncated copies (`test_ksym`). It runs each fixture's dump tests only when `mem.raw` is present, and prints `SKIP` otherwise. With a dump, `test_ksym` decodes kallsyms out of it and diffs every core symbol against `kallsyms.gz`, then checks that every other decoder switch combination is rejected. To fetch a dump:

```sh
cd tests/fixtures/<fixture>
# download <fixture>.mem.raw.zst from the release into this directory as mem.raw.zst, then
zstd -d mem.raw.zst
```

## Recapturing

`collect.py` boots the kernel under plain qemu/kvm (no KVMI needed) with 1 GiB of RAM and `-cpu host`.
It collects the guest side over the serial console, then pauses the guest through the monitor and takes the live read, the registers and the dump.
It refuses to overwrite an existing fixture unless you pass `--force`.

Alpine 6.18 variants (`alpine-standard-3.24.1-x86_64.iso`). Pull `boot/vmlinuz-lts` and `boot/initramfs-lts` out of the iso, e.g. `7z e`:

```sh
A="--kernel vmlinuz-lts --initrd initramfs-lts --iso alpine-standard-3.24.1-x86_64.iso \
   --login root --base-append modules=loop,squashfs,sd-mod,usb-storage"
tests/fixtures/collect.py $A                                    # kaslr_nopti
tests/fixtures/collect.py $A --append pti=on --pause-in user    # kaslr_pti
tests/fixtures/collect.py $A --append nokaslr                   # nokaslr_nopti
```

Ubuntu 5.15. Get `linux-image-5.15.0-198-generic` (from linux-signed) and `linux-modules-5.15.0-198-generic` from the archive, and `busybox-static` from alpine:

```sh
tests/fixtures/mkinitrd-busybox.sh busybox.static lib/modules/5.15.0-198-generic/kernel initrd.gz
tests/fixtures/collect.py --kernel boot/vmlinuz-5.15.0-198-generic --initrd initrd.gz \
    --wait-for RVREADY --config boot/config-5.15.0-198-generic
```

The host these were captured on isn't affected by Meltdown, so without `pti=on` the guests run without KPTI.
