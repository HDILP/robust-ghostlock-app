# OPlus 5.10.226 KernelSU handoff — device gate (2026-11-15) — chain PASS, root BLOCKED

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
| KernelSU module load | **verified-current** — loaded on the 13:10, 15:04 and 15:35 runs; the 3/6 rate was the readiness verdict, not the load |
| Manager signature / crown | verified-current — matches, and the manager is crowned (`uid=10357`) |
| KernelSU userspace half | **pending** — `install=0` on every run: no `/data/adb/ksud`, no `/data/adb/ksu/bin/*` |
| Root usable by apps or shell | blocked by the in-kernel escalation check in `oplus_security_guard` |

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

## Verification entry

Reproduce with the app's normal run, then read `KSU-SUMMARY` in the run log: `seen` / `boot` /
`install` / `manager` / `attempts`, followed by `KSU-DMESG` (drained kernel log tail) and
`KSU-MGRSIGN` (manager certificate). Judge the load from `KernelSU: welcome` in the drained kernel
log, **not** from `install=1` — `install` tracks the userspace half, which this build never completes.
A run whose `KSU-SUMMARY` says `seen=absent` can still have loaded and crowned the module; the 15:04
run did.

