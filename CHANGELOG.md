# Changelog

## 0.2.0 (2026-10-16)

- `panicsight watch`: sample file/vnode headroom and the top per-process fd holders with a 900-second baseline and a 30-second elevated tier, using standard-library ctypes and macOS libproc.
- Escalate at >= 20% file table use, <= 30% free vnodes, WARN status, or >= 5 percentage points of file-table growth since the previous sample. De-escalate after 10 consecutive untriggered samples; share all thresholds with `check`.
- Emit one human-readable line or schema v1 JSONL record per sample, starting immediately, with mode, next interval, trigger conditions, warning/recovery events and matching fd rankings.
- Add single-backup log rotation, bounded record counts, and interruptible SIGTERM/Ctrl-C shutdown. Record process names only; skip inaccessible processes and gracefully handle missing libproc/sysctls. Document measured local overhead and launchd KeepAlive operation.

## 0.1.0 (2026-10-16)

Initial release.

- `panicsight analyze FILE [--json]`: parses the JSON header and body of macOS `panic-full-*.panic` reports, classifies the panic (launchd-exit with signal mapping, watchdog-timeout, other), ranks processes by uninterruptible threads and shared wait events, and prints a verdict line, a suspects table and class-specific hints.
- `panicsight check [--json]`: reads file table and vnode sysctls, prints usage percentages, and warns at >= 50% file table use or < 10% free vnodes.
- Standard library only; Python >= 3.10.
