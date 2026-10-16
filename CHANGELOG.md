# Changelog

## 0.1.0 (2026-10-16)

Initial release.

- `panicsight analyze FILE [--json]`: parses the JSON header and body of macOS `panic-full-*.panic` reports, classifies the panic (launchd-exit with signal mapping, watchdog-timeout, other), ranks processes by uninterruptible threads and shared wait events, and prints a verdict line, a suspects table and class-specific hints.
- `panicsight check [--json]`: reads file table and vnode sysctls, prints usage percentages, and warns at >= 50% file table use or < 10% free vnodes.
- Standard library only; Python >= 3.10.