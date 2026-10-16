import json
import re
import signal
from collections import Counter

STUCK_STATE = "TH_UNINT"
# Kernel threads sit in uninterruptible waits all the time, so pid 0 is not a suspect.
KERNEL_PID = 0
MAX_SUSPECTS = 5
EXCERPT_LEN = 160

_LAUNCHD_RE = re.compile(
    r"initproc exited -- exit reason namespace (\d+) subcode (0x[0-9a-fA-F]+)")


class NotPanicReport(ValueError):
    pass


def parse_report(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise NotPanicReport("cannot read file (%s)" % exc.__class__.__name__) from exc
    parts = text.splitlines(True)
    if len(parts) < 2:
        raise NotPanicReport("not a panic report: no JSON body after the header line")
    header = _load_json(parts[0])
    # Some reports append a plain-text "System Profile:" section after the JSON body.
    body = _load_json("".join(parts[1:]), allow_trailing=True)
    if not isinstance(header, dict) or not isinstance(body, dict):
        raise NotPanicReport("not a panic report: unexpected JSON structure")
    return {"header": header, "body": body}


def _load_json(text, allow_trailing=False):
    try:
        if allow_trailing:
            return json.JSONDecoder().raw_decode(text.lstrip())[0]
        return json.loads(text)
    except (ValueError, TypeError):
        raise NotPanicReport("not a panic report: JSON parsing failed") from None


def classify(panic_string):
    if not isinstance(panic_string, str):
        panic_string = ""
    match = _LAUNCHD_RE.search(panic_string)
    if match:
        namespace = int(match.group(1))
        subcode = int(match.group(2), 16)
        label = "namespace %d subcode 0x%x" % (namespace, subcode)
        sig = _signal_name(subcode) if namespace == 2 else None
        return {"class": "launchd-exit", "signal": sig,
                "label": sig if sig else label, "excerpt": None}
    if "watchdog timeout" in panic_string and "watchdogd" in panic_string:
        return {"class": "watchdog-timeout", "signal": None,
                "label": None, "excerpt": None}
    return {"class": "other", "signal": None, "label": None,
            "excerpt": panic_string[:EXCERPT_LEN]}


def _signal_name(number):
    try:
        return signal.Signals(number).name
    except (ValueError, OverflowError):
        return None


def rank_suspects(body):
    procs = body.get("processByPid")
    if not isinstance(procs, dict):
        return [], 0
    suspects = []
    system_uninterruptible = 0
    for pid_key, proc in procs.items():
        try:
            pid = int(pid_key)
        except (TypeError, ValueError):
            continue
        if pid == KERNEL_PID or not isinstance(proc, dict):
            continue
        threads = proc.get("threadById")
        if not isinstance(threads, dict):
            threads = {}
        stuck = 0
        events = Counter()
        for thread in threads.values():
            if not isinstance(thread, dict):
                continue
            state = thread.get("state")
            states = state if isinstance(state, list) else []
            if STUCK_STATE not in states:
                continue
            stuck += 1
            event = thread.get("waitEvent")
            if isinstance(event, list):
                key = _event_key(event)
                if key is not None:
                    events[key] += 1
        system_uninterruptible += stuck
        if stuck <= 0:
            continue
        top_event, top_count = None, 0
        if events:
            top_event, top_count = events.most_common(1)[0]
        suspects.append({
            "pid": pid,
            "procname": _procname(proc, pid),
            "stuck": stuck,
            "threads": len(threads),
            "top_wait_count": top_count,
            "top_wait_event": list(top_event) if top_event is not None else None,
        })
    suspects.sort(key=lambda item: (-item["stuck"], item["pid"]))
    return suspects, system_uninterruptible


def _event_key(event):
    try:
        return tuple(item if isinstance(item, (int, float)) else str(item)
                     for item in event)
    except (TypeError, ValueError):
        return None


def _procname(proc, pid):
    name = proc.get("procname")
    if isinstance(name, str) and name:
        return name
    return "pid %d" % pid


def analyze(path):
    parsed = parse_report(path)
    header = parsed["header"]
    body = parsed["body"]
    info = classify(body.get("panicString"))
    suspects, system_uninterruptible = rank_suspects(body)
    memory_status = body.get("memoryStatus")
    raw_pressure = memory_status.get("memoryPressure") if isinstance(memory_status, dict) else None
    memory_pressure = raw_pressure if isinstance(raw_pressure, bool) else None
    return {
        "class": info["class"],
        "signal": info["signal"],
        "label": info["label"],
        "excerpt": info["excerpt"],
        "memory_pressure": memory_pressure,
        "system_uninterruptible": system_uninterruptible,
        "suspects": suspects[:MAX_SUSPECTS],
        "os_version": header.get("os_version") if isinstance(header.get("os_version"), str) else None,
        "timestamp": header.get("timestamp") if isinstance(header.get("timestamp"), str) else None,
    }


HINTS = {
    "launchd-exit": "SIGBUS in launchd usually means a failed page-in; check "
                    "whether the file table or vnode table was exhausted "
                    "(sysctl kern.num_files kern.maxfiles), and look at the top suspect.",
    "watchdog-timeout": "A watchdog timeout with no checkins from watchdogd is "
                        "often vnode table exhaustion; check kern.num_vnodes vs "
                        "kern.maxvnodes for the period before the panic.",
}


def render_verdict(result):
    head = result["class"]
    if result["class"] == "launchd-exit" and result["label"]:
        head += " (%s)" % result["label"]
    head += "; memory pressure: %s" % _memory_text(result["memory_pressure"])
    if result["suspects"]:
        top = result["suspects"][0]
        desc = "%s (pid %d): %d of %d threads uninterruptible" % (
            top["procname"], top["pid"], top["stuck"], top["threads"])
        if top["top_wait_count"] > 1:
            desc += ", %d on one wait event" % top["top_wait_count"]
        head += "; top suspect: %s" % desc
    else:
        head += "; top suspect: none"
    head += "; system-wide %d." % result["system_uninterruptible"]
    return head


def _memory_text(value):
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def render_text(result):
    lines = [render_verdict(result), ""]
    if result["suspects"]:
        lines.append("%7s  %-24.24s %5s %7s %8s" % (
            "pid", "process", "stuck", "threads", "top-wait"))
    for suspect in result["suspects"]:
        lines.append("%7d  %-24.24s %5d %7d %8d" % (
            suspect["pid"], suspect["procname"], suspect["stuck"],
            suspect["threads"], suspect["top_wait_count"]))
    if result["excerpt"]:
        lines.append("")
        lines.append("panicString (first %d chars): %s" % (EXCERPT_LEN, result["excerpt"]))
    hint = HINTS.get(result["class"])
    if result["class"] == "launchd-exit" and not result["signal"]:
        hint = None
    if hint:
        lines.append("")
        lines.append("Hints:")
        lines.append("- " + hint)
    return "\n".join(lines)