# panicsight

Find out why your Mac kernel-panicked when it was running AI coding agents.

Agent workloads open files, spawn processes and watch directories at a scale that ordinary desktop use never reaches. On macOS this can exhaust the system file table or the vnode table. Once that happens, launchd cannot page in its own code, dies with SIGBUS, and the kernel panics with `initproc exited -- exit reason namespace 2 subcode 0xa`. The panic report rarely names the process that caused it.

panicsight reads macOS panic reports and points at the likely cause:

- **Post-mortem triage**: classify a `.panic` file (launchd SIGBUS, watchdog timeout, zone exhaustion) and rank the processes that were blocked in the filesystem when the machine went down.
- **Live watch**: sample open files and free vnodes, and name the process behind a spike before the table runs out.

Status: early development. Nothing to install yet.

## License

MIT
