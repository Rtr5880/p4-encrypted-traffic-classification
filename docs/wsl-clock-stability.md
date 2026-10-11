# WSL clock-stability recovery before performance measurement

**Current state:** the native-collector clock audit passed, Linux NTP is restored,
and a fresh 100 pps probe has been prepared. You do not need to stop NTP for
that probe. The isolation commands below document the reversible investigation,
not an additional required service change. Do not start the full sweep yet.

## Evidence and hypothesis

The stopped full run remains diagnostic evidence at
`/home/geleza/p4/etc-training/results/performance_benchmark/20261007T234210Z_763faabe80`.
Its twelve completed trials were invalid. In the four 100 pps measured phases,
wall-clock readings jumped backwards by 811–830 ms while the monotonic clock
continued forwards. Exact input/output sequences remained ordered and complete.
This is not an RF accuracy failure or simply a strict percentile threshold.

Your current Ubuntu is 24.04.2 LTS on WSL 2.4.11 with kernel 5.15.167.4.
`systemd-timesyncd` is enabled and active, and
`/sys/module/hv_utils/parameters/timesync_implicit` reports `Y`.
The Linux NTP polling interval in the failed run was 32 seconds, matching the
observed roughly 32.2-second clock-step spacing. This makes its adjustments a
strong candidate, not yet a conclusively established sole cause.

[Canonical's time-sync guidance](https://ubuntu.com/wsl/docs/stable/explanation/time-sync/)
warns that an independent NTP client can conflict with host time synchronization
on Ubuntu 24.04 and earlier. The installed kernel's exact behavior matters:
enabled Hyper-V synchronization does not by itself prove that it continually
forces sub-second corrections. We will test one reversible change rather than
altering several clock mechanisms together.

## Scoped recovery

1. Save the current boot identity, clock source, time-service state and raw
   realtime/monotonic samples in a **new** baseline audit directory.
2. Temporarily stop **only** `systemd-timesyncd.service` after checking that the
   benchmark is stopped. Do not disable/mask the service or edit `/etc`.
3. Keep Hyper-V synchronization enabled and keep the existing `tsc` clock source.
4. Audit the post-change clock for 180 seconds, spanning multiple previous
   32-second adjustment intervals. Preserve any transitional jump as evidence.
5. Proceed to a separate manual 100 pps probe only after a complete clock audit
   passes. Do not jump straight into the full 240-trial sweep.

Windows Time service status could not supply a running NTP source: the service
was not started. We do not claim accurate UTC or synchronization to a particular
Windows NTP server. The audit establishes observed **interval stability**, not
absolute clock calibration. No Windows time service is started by this procedure.

## Why the audit is needed

The sender uses a monotonic clock. Kernel software packet timestamps used for
path delay are system realtime observations. A wall-clock discontinuity can
produce a negative or biased input/output timestamp difference, even if every
packet is forwarded. The earlier BMv2 internal steady-clock repair does not
repair the OS clock used by these external packet observations.

The new audit tool reads clocks; it sends no packets and changes no service or
clock. It uses the **unchanged** benchmark quality limits: requested 5 ms sampling,
maximum measured-window sampling gap 25 ms, maximum bracket 100 microseconds,
offset displacement below 1 ms, and no backwards realtime/monotonic steps.
The before/after system snapshots and full raw samples are saved separately.
Samples differing from the initial offset are not counted as separate clock
jumps: an adjacent-step summary makes that distinction explicit.

A clean idle audit is necessary but not sufficient. The manual live probe must
also verify kernel packet timestamps, pacing, exact-byte capture, RF accounting,
resource sampling and both workloads under actual traffic.

## Clock-read collector refinement

After your PC restart, the 80-second active-NTP baseline and 180-second
temporarily stopped-NTP audit had no backwards clock steps. Both nevertheless
failed a separate observation-quality gate: maximum read brackets were 139.378
and 133.360 microseconds, respectively, above the unchanged 100-microsecond limit.
Their maximum offset displacements were only 123.863 and 91.801 microseconds.
These observations do not prove that stopping NTP removed the earlier issue.
The stopped service was restored automatically after that failed audit.

The native collector reads the **same** MONOTONIC -> REALTIME -> MONOTONIC
sequence within one C call. Numeric conversion and Python object creation occur
after the third read. It reduces interpreter exposure during the bracket, but
does not make the reads atomic or prevent kernel/hypervisor preemption.
All observations are retained; broad brackets are not discarded or retried;
the 100-microsecond, 25-millisecond and 1-millisecond gates remain unchanged.
Kernel packet timestamp collection and the RF pipeline are unaffected.

Collector source, compiler, shared library and build receipt are hashed. New
benchmark preparations bind this collector explicitly, so the older Python-
collector preparations remain preserved but cannot silently run against changed
instrumentation source. Use only the freshly printed preparation/smoke paths.

The final 180-second native-collector audit with Linux NTP restored **passed**:
36,001 raw samples, no backwards readings, no adjacent offset jumps at or above
1 ms, maximum bracket 27.331 microseconds (limit 100), maximum sampling gap
6.976499 milliseconds (limit 25), and maximum observed offset displacement
14.045 microseconds (limit 1,000). Service/kernel context stayed unchanged.
This validates observed clock quality for that interval, not kernel packet
timestamps or maximum-load performance. The live 100 pps recovery probe remains
necessary. Both NTP-enabled and stopped Python-collector tests already had no
large jumps after reboot, so we do **not** claim NTP isolation conclusively
explained or fixed the earlier 0.8-second events.

Linux NTP is restored, running and still enabled. No clock-source, Windows time
service, `.wslconfig` or persistent service setting was changed. The older Python
instrumentation sources were verified against their saved hashes and copied to
`results/instrumentation_source_backups/20261008T004639Z_3542fee3fe354125a61a3e3b8c88413c`
before the reviewed instrumentation update.

## Commands and their purpose

All commands below belong in your **Ubuntu shell**, directory
`/home/geleza/p4/etc-training`; they are not PowerShell commands. Activation of
the venv is optional because we name its Python executable explicitly.

Read-only baseline, useful to reproduce the problem after a restart:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/audit_wsl_clock.py \
  --seconds 80 --label ntp-active-baseline
```

Temporary stop, performed only as the isolated recovery experiment. It prevents
the Linux NTP daemon from issuing further clock adjustments. It does **not**
disable Windows/Hyper-V synchronization or remove the service's enabled state:

```bash
cd /home/geleza/p4/etc-training
sudo systemctl stop systemd-timesyncd.service
systemctl is-active systemd-timesyncd.service
systemctl is-enabled systemd-timesyncd.service
```

Expect `inactive` and `enabled`, respectively. An inactive service causes
`is-active` to return a nonzero shell status; that is normal for this check.
While it is stopped, avoid `timedatectl timesync-status` and
`timedatectl show-timesync`: those D-Bus queries can activate the daemon again.
Use the `systemctl` state queries above. The auditor deliberately skips the
activating queries when it observes an inactive or unknown service state.

Post-change read-only stability check:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/audit_wsl_clock.py \
  --seconds 180 --label linux-ntp-stopped
```

Do not call a failed audit a pass or remove its outliers. Clock transitions may
need to settle; if so, preserve that failed/transitional run and perform another
new audit after investigating, without changing the acceptance criteria.

Restore the original active service when the temporary test is finished or if
you decide not to retain this runtime arrangement:

```bash
cd /home/geleza/p4/etc-training
sudo systemctl start systemd-timesyncd.service
systemctl is-active systemd-timesyncd.service
```

Restoration can itself adjust the wall clock. Do it **outside** any measurement,
and repeat clock validation before measuring again. Since no persistent disable
is applied, WSL/PC restarts can bring the service back automatically. Recheck
state after any restart. Choosing a permanent policy is separate from this test.

## Manual low-rate probe

Only after the post-change audit passes, prepare a **new** smaller matrix with
the existing harness, without changing its code or quality gates:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_performance_benchmark.py prepare \
  --rates 100 --repetitions 1 \
  --clock-library /home/geleza/p4/etc-training/results/native_clock_bracket/20261008T004640Z_249a014d58734f02bf35392205bc77dd/libetc_clock_bracket.so
```

This makes eight trials: four modes times two workloads. Each retains the normal
5-second warm-up, 20-second measured interval and bounded capture drains. It is
a recovery/instrumentation probe, **not** the final repeated research benchmark.

Use its actual printed preparation directory to run the non-root `smoke` stage.
Then manually launch `run` with that preparation and its matching successful
smoke directory. The full guide is
`/home/geleza/p4/etc-training/docs/performance-benchmark.md`.
The privileged live probe is intentionally not launched automatically.

If all eight pass, review their raw audit and packet timestamps. High-rate
generator pacing remains a separate question: validate it with small new
single-repetition preparations before spending another two hours on the sweep.
No model retraining, feature additions, gate relaxation, Git commit or push is
part of clock recovery.
