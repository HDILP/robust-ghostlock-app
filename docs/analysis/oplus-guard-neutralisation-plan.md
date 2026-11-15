# OPlus `oplus_security_guard` neutralisation — plan (2026-11-15)

Status: **for operator approval.** Decision taken here: **kernel-side, not another round of
late-load reliability work.** Stage 0 is a read-only feasibility gate that runs before any new
native code; Stage 1 is one write through the existing primitive.

Branch `main` @ `f7eea73`. Input: `docs/analysis/device-gates/oplus-5.10.226-ksu-2026-11-15.md`
(six device runs, `20261115-095715` … `20261115-140030`).

## 1. Why reliability work stops here

The gate's own table settles it:

| Surface | State | Consequence for this decision |
|---|---|---|
| Exploit chain (W1 + DirtyFrag) | verified-current | the primitive this plan needs is already proven |
| KernelSU module load | pending — flaky, 3/6 | a 6/6 result changes **nothing** below it |
| Manager signature / crown | verified-current — matches | not a blocker |
| Root usable by apps or shell | blocked by `oplus_security_guard` | the only row that can move the outcome |

Three retry rounds are already in (`386ddd2`, `fe86f42`, `c019100`, `9b0251e`): settle 4 s, three
attempts, mount-first, log-drained readiness. The remaining variance is a kill window whose length
the vendor owns (2.8 s succeeded, 0.4 s died, 4 s both succeeded and missed). More tuning buys a
higher `install=1` rate and still ends in row 4 — a live module whose every root consumer is
killed by process. **Reliability is not the blocker; it is a symptom of it.** The guard kills the
root exec, so neutralizing the guard makes the load reliable as a by-product. Doing it in the
other order is work with no path to the goal.

The same table rules out the userspace direction (fact 4): `su -c id` → SIGKILL,
`ksud debug su` → vendor prompt and a 15 s reboot. Every userspace entry point tested is caught.
The `vrko_selinux_block` pattern (`module-disarm-plan.md`) does not transfer: it blocks a *node*,
and there is no node here — the decision is made in kernel context.

## 2. What the write primitive can and cannot do

From `src/core/memory/payload_builder.h` (single source of truth for the stamp), the chain's write
is a **single pointer-sized store at an arbitrary kernel address**, in one of two shapes:

- **zero write** — leaf layout `{pc = target - 8, right = 0, left = 0}` stores NULL at `*target`,
  tree root never polluted;
- **pointer write** — `{pc = value, right = 0, left = target}` stores `value` at `*target`, with
  `value`'s **low byte forced to 0x00** (`__rb_parent(pc) = pc & ~3`, and W1 already depends on
  byte 0 being 0x00 for `selinux_state.enforcing`).

Two hard consequences, and they shape the whole plan:

1. **No code patching.** There is no text-write path in the tree (`set_memory_rw`, `text_poke`,
   CR0 WP — none present) and the primitive cannot express an instruction stream. So the target
   must be a **data** word: a hook pointer, an ops-table slot, or a feature flag.
2. **Value choice is constrained to two families.** Either zero (only safe if the caller
   NULL-checks) or a pointer whose address ends in `0x00`. Kernel image offsets survive KASLR at
   page granularity, so a gadget/function at image offset ≡ `0x00 (mod 0x100)` stays `0x00` at
   runtime — that is how a "return 0 / return allow" replacement is found offline.

There is **no kernel read primitive** in the tree either. The address is computed as
`base + static_offset`, but **neither term is free** (measured 2026-11-15, run `20261115-140030`):

- `/proc/modules` **redacts every module base to `0x0`** on this build — including
  `oplus_security_guard`, `oplus_secure_harden` and `oplus_security_keventupload`. The "base from
  /proc/modules" step this plan originally assumed does not exist.
- The only address channel observed so far is the guard's own printk, which leaks real pointers
  (`[ROOTCHECK-TRACEP-INFO]__tracepoint_oplus_test base_addr at 0xffffffd2…`,
  `__tracepoint_sys_exit+0x0/0x48: 0xffffffd2…`). Whether `/proc/kallsyms` also yields the module's
  own symbols is unverified and must be checked before Stage 1.

What *is* settled is the write side: W1 has already written a kernel `.data` word on this device
(`policyload before=0 after=2`). "The primitive works" therefore means exactly one thing — a zero
write at a resolved address — and says nothing about patching code or writing an arbitrary value.

## 3. Stage 0 — settle two unknowns before writing code

Read-only. Host work plus one existing device run; **no native change, no new profile field.**

### 3.1 Who kills the process?

Fact 4 records the behaviour but not the actor: `su -c id` returns `Killed` (SIGKILL), while a
path-gated exec returns `execve_block` + exit 137. Those are different code paths, and the 15 s
reboot smells like an escalation, not an execve hook.

The 14:00 log makes this sharper and more urgent than "read the dmesg tail":

- A third module is in play, `oplus_security_keventupload`, and the guard registers a **userspace
  listener** at 7.5 s: `[ROOTCHECK-KEVENTLD-INFO]:kevent_pid is 0xad8` (pid 2776). There is a
  kernel → userspace event channel.
- In the 14:00 run every exec the guard saw was **reported, not blocked**: 18 × `result
  execve_report`, 0 × `execve_block`. The kernel module is at least partly a reporter.

So the question is not "which printk precedes the kill" — a SIGKILL leaves no printk. It is:

1. In a run where `su` is killed, does the kill coincide with a kevent report, and is pid 2776 (or
   its service) the one signalling?
2. Which rule makes the kernel itself return `execve_block` (seen in the 09:57 / 12:02 runs) rather
   than `execve_report` (14:00)? Two different rules, and only one of them is in the module.

- **Kernel-side kill** → continue to 3.2.
- **Userspace consumer decides** → a kernel hook patch only disconnects the alarm. The right target
  is the consumer, and the `module-disarm-plan.md` bind/STOP pattern applies — **this plan is
  withdrawn** and the gate doc records why.

This is the cheapest branch point and it is not yet resolved in writing.

### 3.2 Is the guard reachable through a pointer in writable module data?

Pull `oplus_security_guard.ko` (and `oplus_secure_harden.ko`) — `/vendor/lib/modules/` or the
vendor partition equivalent — and answer three questions offline:

| Question | Why it decides the approach |
|---|---|
| Is the execve/root logic entered through a **pointer** (vendor hook table, `static_call`, an ops struct) or a **direct call** from vmlinux text? | a direct call is not addressable by a data write — the plan dies here, not at run time |
| Which section holds that pointer? | `.data` is writable; `..ro_after_init` would fault and panic the device |
| What does the callee's return contract look like? | decides zero-write vs "return 0" gadget, and whether a NULL is tolerated |

Relocations in the `.ko` name every pointer field; `readelf -r` plus the section table answers all
three without a device.

### 3.3 Confirm the runtime address arithmetic

The module base is **not** in `/proc/modules` (all zero, §2). Two candidates, cheapest first:

1. `/proc/kallsyms` — does it list `oplus_security_guard`'s own symbols (`[oplus_security_guard]`),
   and is it readable in the root shell while permissive? This also decides whether a *symbol*
   target is reachable without any module-base arithmetic at all.
2. The guard's own boot printk (`[ROOTCHECK-TRACEP-INFO]… base_addr at 0x…`), which is already in
   the drained kernel log on every run.

Add one log line to the root script that prints both candidate addresses plus the guard's module
lines — read-back only, no write. This proves the computed target lands in the module's own mapping
before anything is written to it.

## 3A. Stage 0 evidence collected over adb (2026-11-15, no root)

Read-only recon on the device itself (`PJJ110`, same build). Four facts, one of which changes the
shape of the question:

1. **A third-party daemon is the prime suspect, not the module.** `qsguard` runs from
   `/system_ext/bin/qsguard` as uid 1000, `u:r:qsguard:s0`, PPid 1. Its init file is four lines and
   the last one is decisive:

   ```
   service qsguard /system_ext/bin/qsguard
       class late_start
       user system
       group system readproc
       capabilities KILL
   ```

   `CapEff=0x0000000000000020` (bit 5 = CAP_KILL) is set on the live process. `readproc` is the group
   that can read other processes' `/proc`. A daemon whose only privilege is "read /proc and kill" is
   the process-level killer's shape.
2. **It does not poll.** `/proc/2784/stat` over 9 s: `utime=1, stime=0` (≈0 CPU), state `S`, all
   three threads `wchan=0`. It is blocked waiting for something, not scanning `/proc`. So its input
   is a channel, and the channel is what a countermeasure would have to cut.
3. **The kill is not name-based.** A copy of `/system/bin/sh` at `/data/local/tmp/su`
   (`comm=su`, uid 2000) ran 3 s and survived. Whatever the guard keys on, a binary named `su` is
   not sufficient — it needs root credentials or a kernel event.
4. **The guard's own artifacts are root-only.** `/system_ext/bin/qsguard`, `/proc/2784/fd` and
   `/proc/2784/exe` all return `Permission denied` to the shell uid. `/proc/modules` *is* readable
   but every base is `0x0`, so kptr_restrict hides the module mapping from userspace entirely.

Consequence: the two remaining questions — who signals, and what feeds `qsguard` — can only be
answered from the exploit's own root shell. That is why the plan's first code change is a
**read-only probe stage**, not a patch (`guard_probe()` in `write_root_script()`,
`src/core/attack/ops.cpp`):

| probe output | question it answers |
|---|---|
| `/data/local/tmp/ghostlock-guard-<pid>/qsguard.bin` | what `qsguard` links against, what it waits on, whether it calls `kill()` — strings and symbols offline |
| `procs.txt` (`fds:` section, root-only) | the channel: a netlink socket, a binder handle, or a pipe |
| `kallsyms.txt` | whether `/proc/kallsyms` still yields module symbols **and their addresses** to uid 0 — the one input the kernel-side direction (§2) is missing |
| `pkg.txt` | which package owns the "已阻止破坏行为" prompt |

The probe starts nothing, signals nothing and changes no state; it runs before the policy fixup so a
later failure cannot cost the evidence. Side effect worth recording: the generated script is
**18.2 KiB at HEAD and 20.0 KiB with the probe**, against a 20 KiB buffer — 300 bytes of headroom.
The buffer is raised to 32 KiB in the same change.



## 4. Stage 1 — one write, verified by effect

- Extend the profile geometry with the module-relative field offset (the profile is generated
  externally; no bundled profile matches this release, so this is an external-layer field, not a
  schema change to the bundled set).
- Issue exactly one `WriteRequest` at `module_base + static_offset`, choosing the shape from §3.2:
  zero-write for a NULL-checked table slot, otherwise the `0x00`-aligned return-0 replacement.
- **Verification is by effect only**: `su -c id` no longer `Killed`, or `ksud debug su` no longer
  trips the prompt/reboot. There is no read-back path and the plan must not pretend otherwise.
- Single shot per boot. On failure, cold boot and re-read the dmesg tail before the second attempt
  — never loop a write at an address whose section is unconfirmed.

## 5. Stage 2 — re-run the gate

Once the guard is neutralised, the post-fixup kill window is gone and the late-load stops being
flaky. Re-run the six-run series unchanged and expect `install=1` on every run without retry
tuning; keep the existing three-attempt loop as a safety net, and only drop the 4 s settle if the
series shows it is no longer needed. Update the gate doc's Status table row by row.

## 6. Risks

- **`..ro_after_init`.** A write to a read-only-after-init field is a fault, and a fault in kernel
  context is a panic or a reboot loop on a device that already reboots itself after 15 s. §3.2's
  section check is the only thing standing between this plan and that outcome; it is not optional.
- **Three modules, not two.** `oplus_security_guard` (24 KB), `oplus_secure_harden` (16 KB) and
  `oplus_security_keventupload` (20 KB) are all live and interdependent (`/proc/modules` lists the
  last two as used-by the guard). `oem_exec_gate()` only tests the first two by name. Neutralising
  one leaves the other two, and the event uploader is the one that feeds the userspace consumer —
  Stage 0 must say which of the three carries the decision on this build.
- **No read-back.** Every verification is behavioural, so a silent no-op write and a wrong address
  look alike until the effect is tested. One write per boot, then read the log.
- **Escalation.** The device reports a malicious app and reboots after 15 s. A failed Stage 1 is
  not a quiet failure; budget for a cold boot per attempt and keep the attempt count at one.
- **Scope creep.** This plan does not patch text, unload modules, touch KernelSU, or change the
  chain order. If Stage 0 says a data write cannot reach the hook, the answer is a new decision
  point, not a text-patch subsystem smuggled in under this plan.

## 7. Acceptance

- Stage 0 produces a written answer to §3.1, §3.2 and §3.3, each with the artifact it came from.
- Stage 1: one run in which the guard no longer kills a root consumer, with the dmesg tail and the
  `KSU-SUMMARY` block archived next to the gate doc.
- Stage 2: the six-run series shows `install=1` without retry tuning, and the gate doc's Status
  table is updated to say so.
- If §3.1 or §3.2 fails, the deliverable is a documented "not reachable this way" verdict in the
  gate doc — a valid outcome, and cheaper than a blind write.
