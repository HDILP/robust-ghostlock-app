# KernelSU userspace half from the root shell — plan (2026-11-15)

Status: **proposed; batch 1 not yet run.** L-level (the generated root script is exec-stage
content). No change to the route, the payload, the profile schema, the wire format, the Kotlin
contract, or the eight attack functions.

## 现状与基线

- Branch `main` @ `48bb94f`. Device `PJJ110`, `5.10.226-android12-9-o-gbf90590695a1`.
- The chain (W1 + DirtyFrag) is verified-current: root shell `uid=0 u:r:oppo_shell:s0`, 55 s of work,
  never touched by the guard.
- Module load and crown are verified-current on the 13:10 / 15:04 / 15:35 runs.
- **`install=0` on every run.** `ADB-DUMP` prints `ls -la /data/adb` and `ls -la /data/adb/ksu/bin`;
  neither `/data/adb/ksud` nor `/data/adb/ksu/bin/*` exists afterwards.
- The `ksud` daemon dies after `init_module` while the shell that spawned it keeps running. That
  asymmetry is what this plan uses: stop asking `ksud` to install itself, install from the shell.

## 目标与约束

Goal: `/data/adb/ksu/{bin,lib}` and `/data/adb/ksud` exist on disk after a run, and the manager
reports KernelSU as installed.

**Non-goals** (explicit):

- the `su` path — killed by the in-kernel escalation detector, and §3D of
  `oplus-guard-neutralisation-plan.md` closed the kernel-side alternative;
- the app-facing root command channel — next batch, recorded in the device gate's "Next step";
- any change to the guard, the module, or the SELinux policy the fixup already builds.

**Constraints**, each learned the hard way on this device:

1. **No `setuid` family in the root shell.** Credential escalation is exactly what
   `oplus_security_guard` kills for; a `cp`/`mkdir`/`ln` install never calls it.
2. **Root exec of a `/data` binary is refused by path** (`ROOTCHECK execve_block`). This batch
   therefore **copies but never executes** the staged `ksud`; verification is `ls`, not `--version`.
   Confirming a copy by running it would need the `lmkd` bind mount and would buy nothing.
3. **The enforcing window starts at module load, not at `restore_enforce`.** `kernelsu_init` ends
   with `setenforce(true)`, so anything that writes `/data/adb` must run **before**
   `run_late_load` — inside the permissive window the fixup already opens.
4. **The script lives in a 32 KB buffer and is currently ~20.7 KB.** Every edit re-runs the
   extract-C-literals (skipping comments) → `%%`→`%` → `sh -n` check before it can be built.

## 改动清单

| File | Change | Why |
|---|---|---|
| `src/core/attack/ops.cpp` | `write_root_script()`: add a `NO_INSTR`-gated `KSU-USERSPACE-PROBE` block before `run_late_load` (batch 1), later a `KSU-USERSPACE` install block at the same point (batch 2) | the only place the root shell's own script is generated |
| `docs/analysis/device-gates/oplus-5.10.226-ksu-2026-11-15.md` | append the run evidence and flip the userspace-half row from `pending` | gate record |
| `docs/analysis/ksu-userspace-half-plan.md` | this file | design |

## 批次

### 批次 0 — unload the guard module (added 2026-11-15, runs first)

A KSU module cannot be used to attack the guard: KernelSU modules are userspace scripts run by the
`ksud` daemon, and that daemon is exactly what `install=0` is missing. Installing a module to remove
the guard therefore needs the half this document exists to install.

But the guard may not need attacking at all. Measured from `adb shell` at 15:59 on the live device:

- `kernelsu` is `Live`, and `oplus_security_guard` has refcount **0**; `oplus_secure_harden` has
  refcount 1 and that reference is held by `oplus_security_guard`;
- `/system/bin/rmmod` exists (toybox).

A refcount-0 module can be removed with `delete_module`, which needs only `CAP_SYS_MODULE` — carried
by the `init_cred` the chain already installs — and no setuid. Unloading it unregisters the sys_exit
tracepoint handler, which is a stronger result than any write to the module's data could have
produced, and it is the one lever §3D did not consider because it assumed the guard had to be
patched rather than removed.

`git log -S"rmmod"` was empty: this was never tried. The probe runs **before** the KernelSU work so
that, if it succeeds, the same run's `SU-PROBE` executes guard-free — a single run then answers both
"can it be unloaded" and "does `su` work once it is".

What it measures: `CapEff`, `modules_disabled`, the refcount-0 premise, `rmmod` exit codes for both
modules, and the module count afterwards, printed on stdout as `GUARD-BEFORE` / `GUARD-UNLOAD`.

If batch 0 succeeds, batches 1–2 are unnecessary for the stated goal: with the escalation detector
gone, `su` stops being killed, the manager installs the userspace half itself, and modules work. If
it fails (EPERM, `EBUSY`, or `modules_disabled=1`), the failure is recorded in the gate and the
batches below still stand.

### 批次 1 — measure, do not guess

The install layout in the staged binary's strings (`/data/adb/ksu/bin/{ksud,busybox,bootctl,
resetprop}`, `ksu/lib/libadbroot.so`, `.ksurc`) says what `ksud` *looks for*; it does not say what
the manager APK actually ships, nor whether `oppo_shell` may create it. One probe run answers both:

- `ls -la /data/app/*/lib/arm64/` for the manager package — which `lib*.so` actually ship, and their
  exact file names;
- `ls -ldZ /data/adb` plus a `touch /data/adb/.gl-probe && rm -f` round trip — may `oppo_shell`
  create there while permissive, and what label does the new entry get;
- `ls -ldZ /data/adb/ksu /data/adb/modules` if anything already exists.

Batch 1 writes no product files; it only prints. If `touch` fails even while permissive, the whole
approach is wrong and the finding goes in the gate record instead of a batch 2.

### 批次 2 — lay the layout down

Only with batch 1's names: `mkdir -p` the directories, copy `libksud.so` to `ksu/bin/ksud` (0755)
and the other shipped libs to their staged names, `libadbroot.so` to `ksu/lib/`, create
`/data/adb/ksud` (symlink or copy, whichever batch 1 shows the layout expects), write
`.ksurc`/`.feature_config` only if batch 1 shows they exist in the APK. Then `ls -ldZ` the result and
print one `KSU-USERSPACE install=<n> files=<n>` verdict line on **stdout** (stdout survives the
enforcing restore; a `$LOG` write does not).

### 批次 3 — verify and record

Judge from the manager UI (installed / module list) plus the next run's `ADB-DUMP`. Record the gate.

## 数据流/控制流差异

Today: `fixup` → `run_late_load` → `wait_ksu_ready` → `ADB-DUMP` → `restore_enforce` → exit.

With this plan: `fixup` → **userspace stage** → `run_late_load` → `wait_ksu_ready` → `ADB-DUMP`
(now reports the new `/data/adb`) → `restore_enforce` → exit.

The only ordering change is one additive block landing inside the existing permissive window. The
attack stages upstream, the W2 credential repair, and the W3 seccomp clear are not in scope and do
not move.

## 兼容性与回滚

The block is `NO_INSTR`-gated and additive, so a device that cannot take it runs exactly today's
script. Deleting the block restores today's behaviour byte for byte. The files under `/data/adb` are
the deliverable, not a side effect of the chain: a failed run leaves at most a partial layout, which
the next run overwrites, and nothing in the script reads them back.

## 验证矩阵

| Batch | Command / entry | Expected |
|---|---|---|
| 1 | one device run through the app | `KSU-USERSPACE-PROBE` lines in the run log; no reboot; `install=0` may still stand |
| 2 | one device run through the app | `KSU-USERSPACE install=1`; `ADB-DUMP` lists `ksu/bin/*`; manager UI reports installed |
| each edit | extract literals → `%%`→`%` → `sh -n` | parses clean, byte count under the 32 KB buffer |
| each edit | `make -C src ghostlock` | zero warnings |

`cmp_disasm` is **not** required: no attack function body changes. If that stops being true the
batch is out of scope and must be redesigned.

## 明确保留

- The eight attack functions and their `cmp_disasm` baseline — untouched.
- Profile schema, wire format, route catalog, Kotlin contract — untouched.
- The KernelSU module, the `su` path, and the guard — untouched and not fought.
- The `SU-PROBE` block that already reboots the device — left as is; it is evidence for problem 2,
  not a step toward problem 1.

## 进度

- [x] 批次 0 — probe implemented in `9485531`, CI `43692621460` green, APK
      `597b98ed…551cdb` installed on the device at 16:16
- [ ] 批次 0 — **result pending**: runs at 16:17 and 16:19 produced
      `/data/local/tmp/ghostlock-kmsg-{13696,11908}.txt`, but the `GUARD-UNLOAD` verdict goes to the
      run's stdout, which lives in the app's private files dir. The drained kernel log does not carry
      it, and `logcat` no longer has the run. Read it from the app's run log before recording a verdict.
- [ ] 批次 1 — probe run and read the layout names
- [ ] 批次 2 — install block
- [ ] 批次 3 — manager verification, gate record, device gate row flipped
