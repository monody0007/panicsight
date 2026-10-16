import platform
import subprocess

SYSCTL_NAMES = (
    "kern.num_files",
    "kern.maxfiles",
    "kern.maxfilesperproc",
    "kern.num_vnodes",
    "kern.maxvnodes",
    "kern.free_vnodes",
)
FILE_TABLE_WARN_PCT = 50.0
FREE_VNODE_WARN_PCT = 10.0


def default_runner():
    def run(name):
        try:
            proc = subprocess.run(
                ["/usr/sbin/sysctl", "-n", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        try:
            return int(proc.stdout.strip())
        except ValueError:
            return None
    return run


def collect_values(runner):
    return {name: runner(name) for name in SYSCTL_NAMES}


def evaluate(values):
    def pct(part, whole):
        if isinstance(part, int) and isinstance(whole, int) and whole > 0:
            return part / whole * 100.0
        return None

    file_pct = pct(values.get("kern.num_files"), values.get("kern.maxfiles"))
    free_pct = pct(values.get("kern.free_vnodes"), values.get("kern.maxvnodes"))
    warnings = []
    if file_pct is not None and file_pct >= FILE_TABLE_WARN_PCT:
        warnings.append("file table use is %.1f%% of kern.maxfiles (>= %.0f%%)"
                        % (file_pct, FILE_TABLE_WARN_PCT))
    if free_pct is not None and free_pct < FREE_VNODE_WARN_PCT:
        warnings.append("free vnodes are %.1f%% of kern.maxvnodes (< %.0f%%)"
                        % (free_pct, FREE_VNODE_WARN_PCT))
    return {
        "num_files": values.get("kern.num_files"),
        "maxfiles": values.get("kern.maxfiles"),
        "maxfilesperproc": values.get("kern.maxfilesperproc"),
        "num_vnodes": values.get("kern.num_vnodes"),
        "maxvnodes": values.get("kern.maxvnodes"),
        "free_vnodes": values.get("kern.free_vnodes"),
        "file_table_pct": file_pct,
        "free_vnode_pct": free_pct,
        "warnings": warnings,
        "status": "WARN" if warnings else "OK",
    }


def render_text(evaluation):
    raw = (
        ("kern.num_files", "num_files"),
        ("kern.maxfiles", "maxfiles"),
        ("kern.maxfilesperproc", "maxfilesperproc"),
        ("kern.num_vnodes", "num_vnodes"),
        ("kern.maxvnodes", "maxvnodes"),
        ("kern.free_vnodes", "free_vnodes"),
    )
    lines = []
    for name, key in raw:
        value = evaluation.get(key)
        lines.append("%s: %s" % (name, value if value is not None else "unknown"))
    ft = evaluation["file_table_pct"]
    if ft is None:
        lines.append("file table use: unknown")
    else:
        line = "file table use: %.1f%% of kern.maxfiles" % ft
        if ft >= FILE_TABLE_WARN_PCT:
            line += " [WARNING]"
        lines.append(line)
    fv = evaluation["free_vnode_pct"]
    if fv is None:
        lines.append("free vnodes: unknown")
    else:
        line = "free vnodes: %.1f%% of kern.maxvnodes" % fv
        if fv < FREE_VNODE_WARN_PCT:
            line += " [WARNING]"
        lines.append(line)
    lines.append("status: %s" % evaluation["status"])
    for warning in evaluation["warnings"]:
        lines.append("warning: " + warning)
    return "\n".join(lines)


def run_check(runner=None):
    if platform.system() != "Darwin":
        return 2, ("panicsight check requires macOS: sysctl kern.* names "
                   "are unavailable on this platform"), None
    evaluation = evaluate(collect_values(runner or default_runner()))
    return 0, render_text(evaluation), evaluation