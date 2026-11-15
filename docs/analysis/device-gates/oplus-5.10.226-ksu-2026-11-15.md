# OPlus 5.10.226 KernelSU handoff — device gate (2026-11-15) — chain PASS, root BLOCKED

Branch `main` @ `9b0251e` (this fork's own line, not `document`). Six device runs, logs archived in
the app's run folders `20261115-095715` … `20261115-140030`.

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
4. **The vendor guard blocks root at the process level, not at execve.** `adb shell su -c id`
   returns `Killed` (SIGKILL, not `execve_block`), and opening the manager raises the vendor's
   "已阻止破坏行为" prompt. `ksud debug su` (which grants root through `KSU_IOCTL_GRANT_ROOT` and
   then execs `sh`, never executing anything named `su`) is also caught: the system reports a
   malicious app breaking the system and reboots after 15 s.

## Status

| Surface | State |
|---|---|
| Exploit chain (W1 + DirtyFrag) | verified-current on this build |
| KernelSU module load | pending — flaky, 3/6 runs |
| Manager signature / crown | verified-current — matches, not the blocker |
| Root usable by apps or shell | blocked by `oplus_security_guard` |

## Next step

The guard has to go before any root is usable, and disabling it needs the privilege it denies. The
exploit already yields `uid=0` plus an arbitrary kernel write primitive, so the only coherent
direction is a **kernel-side** neutralisation of the guard's execve hook from inside the existing
chain — not more userspace work in the handoff. A userspace-only path would have to survive a guard
that kills by process, and every userspace entry point tested so far is caught.

## Verification entry

Reproduce with the app's normal run, then read `KSU-SUMMARY` in the run log: `seen` / `boot` /
`install` / `manager` / `attempts`, followed by `KSU-DMESG` (drained kernel log tail) and
`KSU-MGRSIGN` (manager certificate). A run that never reaches `install=1` did not load the module and
proves nothing about root.
