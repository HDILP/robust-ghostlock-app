# OPlus 5.10.226 KernelSU handoff — device gate (2026-11-15) — chain PASS, root granted once the guard is unloaded

Branch `main` @ `24f0e1c` (this fork's own line, not `document`). Eight device runs on 2026-11-15: the
first six are archived in the app's run folders `20261115-095715` … `20261115-140030`, and the last
two (≈15:03 and ≈15:35) were driven by the in-app probe stage (`guard_probe`), which copies the vendor
modules and guard artifacts out of the root shell.

## Device and entry

- OPlus phone (OnePlus/realme class; `oplusboot.prjname=23023`, `verifiedbootstate=green`),
  `5.10.226-android12-9-o-gbf90590695a1`, `/data` on F2FS (`s_magic 0xf2f52010`), SELinux starts
  Enforcing. Kernel carries `oplus_security_guard` + `oplus_secure_harden` and the `ROOTCHECK`
  execve hooks.
- Profile: generated externally, `5.10.226-android12-9-o-gbf90590695a1…a1222.conf`, applied as the
  external layer. No bundled profile matches this release.
- Runs driven from the app (base path, no Shizuku); each run exports `log`, `ksu.log`,
  `kernel-info.txt`, `kernel-dmesg.log`, `kmsg-live.txt`, `iomem.txt`.

## What passes

- W1 (SELinux) and the DirtyFrag stage both succeed: `policyload before=0 after=2`, root shell
  `uid=0 context=u:r:oppo_shell:s0`, 28 blocks patched and restored byte-identical.
- KernelSU loads when the vendor's post-reload window is missed: the 13:10 run reached
  `install=1` (`/data/adb/ksud` created) with `RESULT=OK`, and the kernel log carried the full
  `KernelSU: welcome … apply rules … backup sepolicy` sequence 0.2 s after the mount-path exec.
- The manager is the official build. `ksud debug get-sign` reports
  `size: 0x33b, hash: c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6`, byte-identical
  to `KSU_EXPECTED_SIZE`/`KSU_EXPECTED_HASH` in `kernel/Kbuild`, so `is_manager_apk` passes and the
  crown is **not** a blocker.

## Facts established

1. **A root exec from `/data` is refused by path.** A direct `…/files/ksud late-load` is killed
   (`[ROOTCHECK-EXEC-INFO] … result execve_block`, `late-load exit=137`,
   `note: ksud[15908] exited with preempt_count 1`). The same binary bind-mounted over
   `/system/bin/lmkd` runs. `oem_exec_gate()` keys off `oplus_(security_guard|secure_harden)` in
   `/proc/modules` and `/proc/cmdline`.
2. **The kill window after the sepolicy reload has no fixed length.** `oplus_sepolicy_reload:
   Detected illegal porcess reload policy!!!` fires during the fixup; a load 2.8 s later succeeded
   (09:57), one 0.4 s later died (12:02), and a 4 s settle succeeded at 13:10 but missed at 13:34 and
   14:00. Three attempts spaced 4 s still failed twice. Module loading is **not yet reliable**.
3. **`/proc/modules` is not a usable readiness signal.** `kernelsu_init` ends with
   `setenforce(true)`; from that moment `oppo_shell` cannot read `/proc/modules` or `dmesg`, and the
   module is visible for only ~0.2 s. Readiness comes from the drained kernel log
   (`KernelSU: welcome`) or `/data/adb/ksud`. `/data/local/tmp` stays writable across the flip.
4. **The kill is in-kernel, and it fires on credential escalation, not on being root.**
   `adb shell su -c id` returns `Killed` (SIGKILL, not `execve_block`); `ksud debug su` (which grants
   root through `KSU_IOCTL_GRANT_ROOT` and execs `sh`, never executing anything named `su`) is also
   caught, and the device reboots ~15 s later. Measured 2026-11-15: `oplus_root_killed`
   (`.text+0x388` in `oplus_security_guard.ko`) prints `Kill the process of escalation...` and issues
   SIGKILL from the sys_exit tracepoint handler, whose gate is a saved-uid-vs-`cred->uid` comparison
   followed by a jump table over syscalls 143–214 — the `setuid`/`setreuid`/`setresuid` family.
   The exploit's root shell never calls one of those, which is why it runs a full 55 s of work as
   uid 0 while every `su` entry point dies in milliseconds.

## Status

| Surface | State |
|---|---|
| Exploit chain (W1 + DirtyFrag) | verified-current on this build |
| KernelSU module load | **verified-current** — loaded on the 13:10, 15:04, 15:35 and 16:42 runs; the 3/6 rate was the readiness verdict, not the load |
| Manager signature / crown | verified-current — matches, and the manager is crowned (`uid=10357`) |
| KernelSU userspace half | **verified-current** — installed during the 16:42 run: `/data/adb/ksud`, `/data/adb/ksu/bin/{ksud,busybox,bootctl,resetprop}`, `/data/adb/ksu/lib/libadbroot.so`, all stamped 16:43. Every earlier `install=0` was the verdict failing to read `/data/adb`, not the install failing |
| Guard neutralisation by unload | **verified-current** — `GUARD-UNLOAD rc1=0 rc2=0 before=2 after=0` on the 16:42 run; `delete_module` needs no write primitive and no setuid |
| Root usable by apps or shell | **verified-current** — `adb shell su -c id` → `uid=0 … context=u:r:ksu:s0`, and the manager grants apps root (MT Manager). Per boot only: the vendor reloads both guard modules at the next boot and KernelSU still has to be late-loaded by the exploit |

## Next step

The kernel-side direction recorded here on 2026-11-15 is **withdrawn**:
`docs/analysis/oplus-guard-neutralisation-plan.md` §3D shows the chain's write primitive (zero write,
or a pointer write with a `0x00` low byte) cannot reach the check — the early-exit flag is in
`.data..ro_after_init`, the hook count is an immediate, the `.data` hook arrays are never called, and
the decision itself is code.

What the modules establish instead is the shape of the problem: the guard is an **escalation
detector**, and the chain already produces root without escalating. The open direction is therefore
to give that existing root shell a usable command channel, not to keep pushing KernelSU's `su` path
through a detector that is designed to catch exactly that. See
`docs/analysis/oplus-guard-neutralisation-plan.md` §3D before reviving anything from this document.

**Superseded the same day.** A shorter lever exists: the detector is a loadable module with a zero
refcount, so `rmmod` removes it and its tracepoint registration outright — no write primitive, no
`setuid`. Verified on the 16:42 run (`rc1=0 rc2=0 before=2 after=0`), and the run's own aftermath
shows the full chain: `su` granted in `u:r:ksu:s0`, apps rooted, userspace half installed. A separate
command channel is therefore unnecessary — the shell plus a guard-free kernel *is* the channel — and so
is the hand-install of `/data/adb`.

What it does **not** give is persistence. The vendor reloads both guard modules at boot and KernelSU is
still late-loaded by the exploit every time, so root dies with the reboot. The next step is a KernelSU
module that runs `rmmod` in `post-fs-data.sh` / `service.sh`, which is now possible precisely because
the userspace half exists. The other open item is the verdict itself: it has to stop reporting failure
after a run that worked, which means computing it before the enforcing flip (see the table above).

## Guard mechanism (measured 2026-11-15, from the modules themselves)

`/vendor/lib/modules` is root-only, so these were copied out by the run's own root shell. Fingerprints
are recorded here so a future run can tell whether the vendor modules changed:

| File | SHA-256 |
|---|---|
| `oplus_security_guard.ko` (31,872 B) | `a02a5321ee73b5479a7341fd6f45c24d361cce5f8b82fae98c0c21bd73e22ece` |
| `oplus_secure_harden.ko` (31,032 B) | `a18bea37cbe5e5eb6e80a5aa9f1b7ca167fcfbe743c7be9be6221d8c61c3cfe4` |
| `oplus_security_keventupload.ko` (16,080 B) | `1f9e122e72f8d00f0c0aac4177f003c38fd2c684a1c860cd7ad44906d0982386` |
| `/system_ext/bin/qsguard` (70,192 B) | `855cde24696500327690c7bf4d25fa22d83d04b74c9bf39d6c67592f20eed516` |

- `oplus_security_guard.ko` keeps its `.symtab`: `oplus_root_killed` `.text+0x388`,
  `oplus_root_check_post_handler` `.text+0x3e8`, `g_boot_state` `.data..ro_after_init+0x0`,
  `oplus_pre_hook_array` `.data+0x10`, `oplus_post_hook_array` `.data+0x40`.
- The block dialog is drawn by `com.oplus.exsystemservice`
  (`/system_ext/priv-app/OplusExSystemService`), uid 1000, `u:r:system_app:s0`, **`CapEff=0`**, and
  contains `antirootdialog/OplusAntiRootDialogService`. It is the face of the block, not its
  mechanism: it has no capability to kill anything.
- `qsguard` is **not** a security daemon. It is Qualcomm's SurfaceFlinger watchdog (`qsguard detect UI
  Freeze`, `Detect Screen freeze!! ... vsync timeout`); its `CAP_KILL` exists to kill a hung
  surfaceflinger. `vendor.dpmd` is Qualcomm's Data Port Manager. Both were suspects and are cleared.
- Address sources are all closed even for uid 0: `/proc/modules` reports every module base as
  `0x0`, `/proc/kallsyms` lists 174 `[oplus_security_guard]` symbols with every address `0x0`, and
  `/sys/module/*/sections/*` is root-only.

### The guard set on this device, and a module that does not match it

Measured 2026-11-15 16:32 from `adb shell`, after a reboot (uptime 98 s):

| Module | Refcount | Held by |
|---|---|---|
| `oplus_security_guard` | 0 | — |
| `oplus_secure_harden` | 1 | `oplus_security_guard` |
| `oplus_security_keventupload` | 2 | `oplus_security_guard`, `oplus_secure_harden` |
| `oplusboot` | 7 | the guard set plus `qcom_q6v5_pas`, `dump_device_info`, … |

`/system/bin/rmmod` exists (toybox). The zero refcount means `delete_module` can remove
`oplus_security_guard` outright, and only then `oplus_secure_harden` — the reverse order is `EBUSY`.
That lever is unrelated to §3D: §3D shows the write primitive cannot change the *check*, while unloading
removes the whole module and its tracepoint registration.

**Trap.** The widely circulated KernelSU module `unload_oplus_secure_guard_new` targets
`oplus_secure_guard_new` — the newer ColorOS module that blocks non-root exec of `/data/adb/**`
(`[secureguard_new][root_check] … execve_block`). **This device does not have that module.** Its
`loaded()` grep is therefore always false, it prints "already unloaded, nothing to do" and exits: it
installs cleanly, reports success, and does nothing. A module that says it worked is not evidence;
only `/proc/modules` losing the entry is.

### Guard unload — the run that removed the detector (2026-11-15 16:42)

Run folder `20261115-164233` (nine device runs before it; this is the ninth-plus, exported by the app
because `run-as` is unavailable on a release build):

```
GUARD-BEFORE count=2 cap=000001ffffffffff modules_disabled=0 rmmod=/system/bin/rmmod
GUARD-UNLOAD rc1=0 rc2=0 before=2 after=0
```

Both guard modules left `/proc/modules` with no error, with all capabilities present and
`modules_disabled=0`. **That is the load-bearing result**: the escalation detector can be removed
outright, and `delete_module` needs neither a write primitive nor `setuid` — the part §3D never
covered, because it only asked whether the *check* could be edited.

**The app's `RESULT=FAIL` on that run was a false negative.** Measured afterwards on the same boot
(uptime 1059 s), with the run long finished:

```
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
$ grep -cE '^oplus_(security_guard|secure_harden) ' /proc/modules
0
$ ls -la /data/adb/ksu/bin            # all created 16:43, during that run
ksud -> /data/adb/ksud   busybox   bootctl   resetprop
$ ls -la /data/adb/ksu/lib
libadbroot.so
```

That run unloaded the detector, KernelSU loaded and stayed live, `su` was granted in `u:r:ksu:s0` —
the correct domain, not the exploit's `oppo_shell` — the manager passed it on to apps (MT Manager ran
with full root), and **the userspace half installed itself**: the exact thing that had been
`install=0` for nine runs. The first reading of this log took `seen=absent` at face value and
concluded the opposite; the device state is what settled it.

**Why the verdict lies, structurally.** Every readiness signal needs root access the shell loses at the
enforcing flip, so none of them is evidence once the flip has happened:

| Signal | Why it is unreadable at check time |
|---|---|
| `seen=absent` from `/proc/modules` | after `setenforce(true)` `oppo_shell` cannot read `/proc/modules` at all |
| `install=0` from `/data/adb/ksud` | the same run's own `ADB-DUMP` prints `ls: /data/adb: Permission denied` |
| `su=absent` from `/data/adb/ksu/bin/su` | same directory, same denial |
| the drained kernel log | the drain's writes fail too — `can't create …txt.new: Permission denied` — so `kmsg-live.txt` stops 22 s before the interesting part and carries no `KernelSU: welcome` |

This is the trap `AGENTS.md` already records for `/proc/modules`, one step further: `install` and `su`
are not independent evidence either, and "check more carefully" cannot fix it. The verdict has to be
computed **before** the flip, or through something that survives it.

**Ordering is not the defect.** Unloading before the late-load is what let KernelSU's `su` work in the
same run. An earlier revision of this section called for moving the unload after `wait_ksu_ready`;
that is withdrawn. What needs to move is the verdict, not the unload.

## Verification entry

Reproduce with the app's normal run, then read `KSU-SUMMARY` in the run log: `seen` / `boot` /
`install` / `manager` / `attempts`, followed by `KSU-DMESG` (drained kernel log tail) and
`KSU-MGRSIGN` (manager certificate). Judge the load from `KernelSU: welcome` in the drained kernel
log, **not** from `install=1` — `install` tracks the userspace half, which this build never completes.
A run whose `KSU-SUMMARY` says `seen=absent` can still have loaded and crowned the module; the 15:04
run did.

## 2026-11-28 — code reverted, the unload promoted to the product path

The branch went back to the r11 mainline (`76e10067`) for everything that judged or retried the
KernelSU handoff: the ready-state poll over the drained kernel log, the widened late-load retries,
the staging of a su-free entry, and the probe stage (`guard_probe`, `GUARD-BEFORE`). Only the
load-bearing lever survives, and it leaves the instrumentation gate: `write_root_script()` now
unloads `oplus_security_guard` and then `oplus_secure_harden` unconditionally — present-only,
non-fatal, before the policy fixup and the late-load — logging
`GUARD-UNLOAD md=… before=… rc1=… rc2=… after=…`.

What that changes in the rows above: the unload result stands (it is what made `su` work), the
KernelSU load and the userspace half stand, and the run-local verdict is back to the mainline one —
still `RESULT=FAIL` on a run that worked, for the reason in "Why the verdict lies". The verdict was
deliberately left alone in this revert. Judge this device from `su -c id`, `/proc/modules` and
`/data/adb`, not from the run log's bottom line.

