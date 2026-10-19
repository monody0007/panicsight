import math
import re
import platform
import subprocess

SYSCTL_NAMES = (
    "kern.num_files",
    "kern.maxfiles",
    "kern.maxfilesperproc",
    "kern.num_vnodes",
    "kern.maxvnodes",
    "kern.free_vnodes",
    "vm.loadavg", "hw.logicalcpu", "vm.swapusage", "hw.memsize",
    "kern.memorystatus_level",
)
FILE_TABLE_WARN_PCT = 50.0
FREE_VNODE_WARN_PCT = 10.0
ELEVATED_FILE_TABLE_PCT = 20.0
ELEVATED_FREE_VNODE_PCT = 30.0
GROWTH_PCT_POINTS = 5.0
DEESCALATE_AFTER_SAMPLES = 10


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
        return parse_sysctl(name, proc.stdout)
    return run


PRESSURE_DEFAULTS = {
    "load_elevated_per_core": 1.5,
    "swap_growth_bytes": 2 * 1024**3,
    "load_warn_per_core": 3.0,
    "swap_warn_pct_of_ram": 25.0,
    "memory_warn_level": 40.0,
    "load_recover_per_core": 2.0,
    "swap_recover_pct_of_ram": 20.0,
    "memory_recover_level": 50.0,
}
PRESSURE_FIELDS = (
    "load_avg", "ncpu", "load1_per_core", "load5_per_core", "swap_used_bytes",
    "swap_total_bytes", "memsize_bytes", "swap_used_pct_of_ram", "memorystatus_level",
)


def parse_sysctl(name, text):
    try:
        if name == "vm.loadavg":
            values = [float(v) for v in text.strip().strip("{} ").split()]
            return values if len(values) == 3 and all(math.isfinite(v) and v >= 0 for v in values) else None
        if name == "vm.swapusage":
            values = {}
            for key in ("used", "total"):
                match = re.search(r"\b%s\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT])\b" % key, text, re.I)
                if not match:
                    return None
                values[key] = int(float(match[1]) * 1024 ** ("KMGT".index(match[2].upper()) + 1))
            return values
        value = int(text.strip())
        return value if value >= 0 else None
    except (ValueError, OverflowError):
        return None


def pressure_values(values):
    loads, cpu = values.get("vm.loadavg"), values.get("hw.logicalcpu")
    swap = values.get("vm.swapusage") or {}
    ram = values.get("hw.memsize")
    used = swap.get("used")
    return {"load_avg": loads, "ncpu": cpu,
            "load1_per_core": loads[0] / cpu if loads is not None and cpu else None,
            "load5_per_core": loads[1] / cpu if loads is not None and cpu else None,
            "swap_used_bytes": used, "swap_total_bytes": swap.get("total"),
            "memsize_bytes": ram,
            "swap_used_pct_of_ram": used / ram * 100 if used is not None and ram else None,
            "memorystatus_level": values.get("kern.memorystatus_level")}


def pressure_warnings(sample, thresholds=None, active=None):
    """Unknown readings never warn; watch supplies the preceding category state.

    Contract: each warning starts with the field that triggered it (`load5_per_core=` or
    `swap_used_pct_of_ram=`), so log consumers can classify warnings by prefix.
    """
    t = PRESSURE_DEFAULTS if thresholds is None else thresholds
    prior = active or set()
    warnings, current = [], set()
    load, swap, level = (sample.get(k) for k in
                         ("load5_per_core", "swap_used_pct_of_ram", "memorystatus_level"))
    if load is not None and load >= t["load_recover_per_core" if "load" in prior else "load_warn_per_core"]:
        current.add("load")
        warnings.append("load5_per_core=%.2f (warn >= %g; recover < %g)" %
                        (load, t["load_warn_per_core"], t["load_recover_per_core"]))
    memory = (swap is not None and level is not None and
              (swap >= t["swap_recover_pct_of_ram"] and level <= t["memory_recover_level"]
               if "memory" in prior else
               swap >= t["swap_warn_pct_of_ram"] and level <= t["memory_warn_level"]))
    if memory:
        current.add("memory")
        warnings.append("swap_used_pct_of_ram=%.2f, memorystatus_level=%g (warn >= %g and <= %g)" %
                        (swap, level, t["swap_warn_pct_of_ram"], t["memory_warn_level"]))
    return warnings, current


def collect_values(runner):
    return {name: runner(name) for name in SYSCTL_NAMES}


def evaluate(values, thresholds=None):
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
    pressure = pressure_values(values)
    warnings.extend(pressure_warnings(pressure, thresholds)[0])
    return {
        **pressure,
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
    for key in PRESSURE_FIELDS:
        lines.append("%s: %s" % (key, evaluation.get(key) if evaluation.get(key) is not None else "unknown"))
    lines.append("status: %s" % evaluation["status"])
    for warning in evaluation["warnings"]:
        lines.append("warning: " + warning)
    return "\n".join(lines)


def run_check(runner=None, thresholds=None):
    if platform.system() != "Darwin":
        return 2, ("panicsight check requires macOS: sysctl kern.* names "
                   "are unavailable on this platform"), None
    evaluation = evaluate(collect_values(runner or default_runner()), thresholds)
    return 0, render_text(evaluation), evaluation
