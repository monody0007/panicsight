# panicsight

Find out why your Mac kernel-panicked when it was running AI coding agents.

Agent workloads open files, spawn processes and watch directories at a scale that ordinary desktop use never reaches. On macOS this can exhaust the system file table or the vnode table. Once that happens, launchd cannot page in its own code, dies with SIGBUS, and the kernel panics with `initproc exited -- exit reason namespace 2 subcode 0xa`. The panic report rarely names the process that caused it.

The investigation that led to this tool is written up in [AI agents pushed my Mac into a kernel panic](https://anydoor7.com/blog/agent-kernel-panic-pagefind); the fix for the tool involved is [Pagefind PR #1380](https://github.com/Pagefind/pagefind/pull/1380).

panicsight reads macOS panic reports and points at the likely cause:

- **Post-mortem triage**: classify a `.panic` file (launchd exit with its signal, watchdog timeout, other) and rank the processes that were blocked in the filesystem when the machine went down.
- **Resource check**: `panicsight check` reports how full the file table and vnode table are right now, so you can watch them during large builds. A continuous watch mode that names the process behind a spike is planned.

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

## License

MIT