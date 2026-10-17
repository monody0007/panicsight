# panicsight

Find out why your Mac kernel-panicked when it was running AI coding agents.

Agent workloads open files, spawn processes and watch directories at a scale that ordinary desktop use never reaches. On macOS this can exhaust the system file table or the vnode table. Once that happens, launchd cannot page in its own code, dies with SIGBUS, and the kernel panics with `initproc exited -- exit reason namespace 2 subcode 0xa`. The panic report rarely names the process that caused it.

The investigation that led to this tool is written up in [AI agents pushed my Mac into a kernel panic](https://anydoor7.com/blog/agent-kernel-panic-pagefind); the fix for the tool involved is [Pagefind PR #1380](https://github.com/Pagefind/pagefind/pull/1380).

panicsight reads macOS panic reports and points at the likely cause:

- **Post-mortem triage**: classify a `.panic` file (launchd exit with its signal, watchdog timeout, other) and rank the processes that were blocked in the filesystem when the machine went down.
- **Resource check**: `panicsight check` reports how full the file table and vnode table are right now.
- **Continuous watch**: `panicsight watch` samples file/vnode headroom and the top file-descriptor holders, switching between a 15-minute baseline and a 30-second elevated tier.

## Install

Requires Python 3.10 or newer. No runtime dependencies, standard library only.

```sh
pipx install git+https://github.com/monody0007/panicsight
```

## Usage

### `panicsight analyze FILE [--json]`

Classify a panic report written by macOS to `/Library/Logs/DiagnosticReports/panic-full-*.panic`, rank the processes by uninterruptible (`TH_UNINT`) threads, and print a verdict plus hints.

```text
launchd-exit (SIGBUS); memory pressure: no; top suspect: pagefind_extended (pid 1234): 512 of 515 threads uninterruptible, 511 on one wait event; uninterruptible threads outside the kernel: 515.

    pid  process                  stuck threads top-wait
   1234  pagefind_extended          512     515      511
     99  mds_stalled                  3       3        3

Hints:
- SIGBUS in launchd usually means a failed page-in; check whether the file table or vnode table was exhausted (sysctl kern.num_files kern.maxfiles), and look at the top suspect.
```

`--json` prints a single machine-readable object instead (keys `class`, `signal`, `memory_pressure`, `system_uninterruptible`, `suspects`, `os_version`, `timestamp`, `excerpt`). A file that is not a panic report exits with code 2 and a one-line error.

### `panicsight check [--json]`

Reads `kern.num_files`, `kern.maxfiles`, `kern.maxfilesperproc`, `kern.num_vnodes`, `kern.maxvnodes` and `kern.free_vnodes`, and warns when the file table is at or above 50% of `kern.maxfiles` or free vnodes drop below 10% of `kern.maxvnodes`.

```text
$ panicsight check
kern.num_files: 12650
kern.maxfiles: 491520
kern.maxfilesperproc: 245760
kern.num_vnodes: 263168
kern.maxvnodes: 263168
kern.free_vnodes: 182237
file table use: 2.6% of kern.maxfiles
free vnodes: 69.2% of kern.maxvnodes
status: OK
```

### `panicsight watch`

Continuously sample the same six sysctls as `check`, together with per-process
fd counts from macOS libproc. The first sample is immediate, and every sample
produces exactly one record. Without `--log`, each record is one human-readable
stdout line. With `--log`, append schema v1 JSONL, creating parent directories:

```sh
panicsight watch --log ~/Library/Logs/panicsight/watch.jsonl
# A short smoke test:
panicsight watch --count 3 --baseline-interval 1 --elevated-interval 1
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--baseline-interval SECONDS` | `900` | Baseline interval, integer >= 1 second. |
| `--elevated-interval SECONDS` | `30` | Elevated interval, integer >= 1 and <= baseline. |
| `--log PATH` | stdout | Append JSONL instead of human-readable text. |
| `--top N` | `5` | Positive number of top fd holders to record. |
| `--max-bytes N` | `5000000` | Rotate when the log exceeds N bytes, replacing `PATH.1`; retain exactly one backup. |
| `--count N` | forever | Stop after N samples/records. |

Watch starts in **baseline** mode (15 minutes). A sample switches it to
**elevated** mode (30 seconds) if any of these conditions fires:

- File table use is **>= 20%** of `kern.maxfiles` (`file_table_pct>=20`).
- Free vnodes are **<= 30%** of `kern.maxvnodes` (`free_vnode_pct<=30`).
- `check` reports **WARN** (`status=WARN`): file table use >= 50% or free vnodes < 10%.
- File table use rises **>= 5 percentage points** since the immediately previous
  sample (`growth>=5pp`). This is a percentage-point change, not a relative increase.

After **10 consecutive untriggered samples**, watch returns to baseline. Any
trigger resets that counter. Unknown values (`null`) never trigger; an unknown
file-table percentage also breaks the growth comparison with older samples.
The next wait uses the mode selected by the current sample. Collection time is
additional to that wait; slow probes do not cause catch-up bursts. This trade-off
keeps routine sampling cheap, but changes between baseline samples can take up
to 15 minutes to be noticed.

`mode` and `next_interval_s` describe the mode after this sample's transitions.
`events` lists `escalate`/`deescalate` on tier changes and `warn`/`recover` on
OK-to-WARN/WARN-to-OK changes. A first sample in WARN emits `warn` too. Multiple
events share one record, and persistent WARN does not repeat `warn`. `triggers`
lists every condition fired by this sample. Timestamps use local UTC offset and
seconds precision. SIGTERM and Ctrl-C interrupt even a 900-second wait and exit 0.

Example JSONL line (illustrative values):

```json
{"schema":1,"ts":"2026-10-16T12:00:00-07:00","mode":"elevated","next_interval_s":30,"events":["escalate"],"triggers":["file_table_pct>=20"],"num_files":100000,"maxfiles":491520,"maxfilesperproc":245760,"num_vnodes":263168,"maxvnodes":263168,"free_vnodes":180000,"file_table_pct":20.345052083333336,"free_vnode_pct":68.39737354085604,"status":"OK","warnings":[],"thresholds":{"file_table_warn_pct":50.0,"free_vnode_warn_pct":10.0,"file_table_elevated_pct":20.0,"free_vnode_elevated_pct":30.0,"growth_pct_points":5.0},"top_fd":[{"pid":1234,"name":"Python","fds":4116}]}
```

Only pid, process name (basename) and fd count are recorded for each holder;
paths, argv and cwd are never collected. Counts use libproc's buffer-size
estimate (`proc_pidinfo(..., PROC_PIDLISTFDS, ..., NULL, 0) / 8`) and can exceed
the number of open descriptors. In a local discrimination test, a Python child
holding 3000 `/dev/null` fds ranked first in all three samples, with an estimate
of 4116. Inaccessible or exited processes are silently skipped. Missing sysctls
become `null`; on platforms without libproc, `top_fd` is empty.

Each complete line is written in one `write` followed by `flush`. Readers should
ignore a trailing incomplete line and reopen the log after rotation. Rotation
happens after a complete record (or on opening an already oversized log), so a
file can exceed the limit by one record and the new active log can be empty.

This mode is meant to run under **launchd with `KeepAlive`** for continuous
collection and automatic restarts. Use absolute executable and log paths in
`ProgramArguments`; launchd does not expand `~` or shell variables. Leave
`--count` unset for continuous operation. No launchd job is installed by
panicsight. Records are flushed to the OS after each line; survival of the last
write through a kernel panic depends on filesystem caching.

Measured on macOS 27.0.1 arm64, Python 3.14.7 (2026-10-16):
`/usr/bin/time -l` over `watch --count 3 --baseline-interval 1 --elevated-interval 1`
with JSONL output took **2.10 s wall, 0.05 s user CPU and 0.03 s system CPU**,
including startup and two 1-second waits (about 33 ms non-wait wall time and
27 ms CPU per record when amortized). Separately timing the three collection
calls gave **14.83 ms wall and 13.54 ms CPU per sample on average**, including
sysctl child CPU; collection excludes startup, output and waits. These are local
measurements, not a performance guarantee.

## License

MIT
