"""Continuous resource sampling; only process names leave the fd enumerator."""

import ctypes
from datetime import datetime
import json
import os
from pathlib import Path
import platform
import signal
import sys
import subprocess
import threading

from panicsight import check

PROC_PIDLISTFDS = 1


class ProcFdInfo(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_int32), ("type", ctypes.c_uint32)]


def enumerate_fds():
    """Return pid/name/fds only, skipping inaccessible or vanished processes."""
    if platform.system() != "Darwin":
        return []
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.proc_listallpids.restype = ctypes.c_int
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                    ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        lib.proc_name.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_name.restype = ctypes.c_int
    except (OSError, AttributeError):
        return []
    needed = lib.proc_listallpids(None, 0)
    if needed <= 0:
        return []
    # Leave room for processes born between the sizing and enumeration calls.
    pids = (ctypes.c_int * (needed + 32))()
    found = lib.proc_listallpids(pids, ctypes.sizeof(pids))
    holders = []
    for pid in pids[:max(0, min(found, len(pids)))]:
        if pid <= 0:
            continue
        size = lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, None, 0)
        if size <= 0:
            continue
        buffer = ctypes.create_string_buffer(size)
        copied = lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, size)
        if copied == size:
            # Fds may have opened since sizing; retry once with more room.
            size *= 2
            buffer = ctypes.create_string_buffer(size)
            copied = lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, size)
        if copied <= 0:
            continue
        name = ctypes.create_string_buffer(1024)
        if lib.proc_name(pid, name, len(name)) <= 0:
            continue
        basename = os.path.basename(os.fsdecode(name.value))
        if basename:
            holders.append({"pid": pid, "name": basename,
                            "fds": copied // ctypes.sizeof(ProcFdInfo)})
    return holders


def collect_sample(runner, fd_enumerator, top, now, thresholds=None):
    """Keep the headroom values and fd ranking from the same sampling pass."""
    timestamp = now().astimezone().isoformat(timespec="seconds")
    evaluation = check.evaluate(check.collect_values(runner), thresholds)
    holders = sorted(fd_enumerator(), key=lambda item: (-item["fds"], item["pid"]))
    return {"ts": timestamp, **evaluation,
            "top_fd": [{"pid": item["pid"],
                        "name": os.path.basename(item["name"]),
                        "fds": item["fds"]} for item in holders[:top]]}


class TierState:
    """Apply transitions using only this sample and the immediately previous one."""

    def __init__(self, thresholds=None):
        self.thresholds = dict(check.PRESSURE_DEFAULTS if thresholds is None else thresholds)
        self.pressure_active = set()
        self.previous_swap = None
        self.mode = "baseline"
        self.previous_file_pct = None
        self.previous_status = "OK"
        self.untriggered_samples = 0

    def update(self, sample):
        file_pct, free_pct = sample["file_table_pct"], sample["free_vnode_pct"]
        triggers, events = [], []
        # Re-evaluate only pressure reasons with hysteresis, leaving file/vnode reasons untouched.
        base = [w for w in sample["warnings"] if not w.startswith(("load5_per_core=", "swap_used_pct_of_ram="))]
        pressure, self.pressure_active = check.pressure_warnings(sample, self.thresholds, self.pressure_active)
        sample["warnings"] = base + pressure
        sample["status"] = "WARN" if sample["warnings"] else "OK"
        load, swap = sample.get("load1_per_core"), sample.get("swap_used_bytes")
        if load is not None and load >= self.thresholds["load_elevated_per_core"]:
            triggers.append("load1_per_core>=%g" % self.thresholds["load_elevated_per_core"])
        if (swap is not None and self.previous_swap is not None and
                swap - self.previous_swap >= self.thresholds["swap_growth_bytes"]):
            triggers.append("swap_growth_bytes>=%g" % self.thresholds["swap_growth_bytes"])
        self.previous_swap = swap
        if file_pct is not None and file_pct >= check.ELEVATED_FILE_TABLE_PCT:
            triggers.append("file_table_pct>=%g" % check.ELEVATED_FILE_TABLE_PCT)
        if free_pct is not None and free_pct <= check.ELEVATED_FREE_VNODE_PCT:
            triggers.append("free_vnode_pct<=%g" % check.ELEVATED_FREE_VNODE_PCT)
        if sample["status"] == "WARN":
            triggers.append("status=WARN")
        if (file_pct is not None and self.previous_file_pct is not None
                and file_pct - self.previous_file_pct >= check.GROWTH_PCT_POINTS):
            triggers.append("growth>=%gpp" % check.GROWTH_PCT_POINTS)

        if triggers:
            self.untriggered_samples = 0
            if self.mode == "baseline":
                self.mode = "elevated"
                events.append("escalate")
        elif self.mode == "elevated":
            self.untriggered_samples += 1
            if self.untriggered_samples >= check.DEESCALATE_AFTER_SAMPLES:
                self.mode = "baseline"
                self.untriggered_samples = 0
                events.append("deescalate")
        if sample["status"] != self.previous_status:
            events.append("warn" if sample["status"] == "WARN" else "recover")
        self.previous_file_pct = file_pct
        self.previous_status = sample["status"]
        return events, triggers


def make_record(sample, mode, next_interval, events, triggers, thresholds=None):
    return {"schema": 1, "ts": sample["ts"], "mode": mode,
            "next_interval_s": next_interval, "events": events, "triggers": triggers,
            **{key: sample[key] for key in (
                "num_files", "maxfiles", "maxfilesperproc", "num_vnodes",
                "maxvnodes", "free_vnodes", "file_table_pct", "free_vnode_pct",
                "status", "warnings")},
            **{key: sample.get(key) for key in check.PRESSURE_FIELDS},
            "thresholds": {"file_table_warn_pct": check.FILE_TABLE_WARN_PCT,
                           "free_vnode_warn_pct": check.FREE_VNODE_WARN_PCT,
                           "file_table_elevated_pct": check.ELEVATED_FILE_TABLE_PCT,
                           "free_vnode_elevated_pct": check.ELEVATED_FREE_VNODE_PCT,
                           "growth_pct_points": check.GROWTH_PCT_POINTS,
                           **(check.PRESSURE_DEFAULTS if thresholds is None else thresholds)},
            "top_fd": sample["top_fd"]}


def render_text(record):
    def percentage(value):
        return "unknown" if value is None else "%.1f%%" % value

    holders = ", ".join("%s (pid %d): %d" % (
        json.dumps(item["name"], ensure_ascii=True), item["pid"], item["fds"])
        for item in record["top_fd"]) or "none"
    return ("%s %s %s next=%ds events=[%s] triggers=[%s] "
            "file_table=%s free_vnodes=%s top_fd=[%s]%s" % (
        record["ts"], record["mode"], record["status"], record["next_interval_s"],
        ",".join(record["events"]), ",".join(record["triggers"]),
        percentage(record["file_table_pct"]), percentage(record["free_vnode_pct"]),
        holders, " warnings=" + "; ".join(record["warnings"]) if record["warnings"] else ""))


class LogLockedError(OSError):
    """Another writer holds the lock for this log path."""


class RecordWriter:
    """Append full lines, flushing each one, with a single rotating backup."""

    def __init__(self, path=None, max_bytes=5_000_000, stream=None):
        self.path = Path(path) if path is not None else None
        self.max_bytes = max_bytes
        self.stream = stream if stream is not None else sys.stdout
        self.file = None
        self.lock_file = None

    def __enter__(self):
        if self.path is not None:
            import fcntl

            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.lock_file = Path(str(self.path) + ".lock").open("a")
                try:
                    fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise LogLockedError(
                        "another panicsight watch is already writing %s" % self.path) from exc
                self.file = self.path.open("a", encoding="utf-8")
                self._rotate()
            except OSError:
                self.__exit__(*sys.exc_info())
                raise
        return self

    def _rotate(self):
        if self.file.tell() > self.max_bytes:
            previous, self.file = self.file, None
            previous.close()
            self.path.replace(Path(str(self.path) + ".1"))
            self.file = self.path.open("a", encoding="utf-8")

    def write(self, record):
        if self.path is not None and self.file is None:
            self.file = self.path.open("a", encoding="utf-8")
        target = self.file if self.path is not None else self.stream
        line = (json.dumps(record, separators=(",", ":"), ensure_ascii=True)
                if self.path is not None else render_text(record)) + "\n"
        try:
            target.write(line)
            target.flush()
            if self.file is not None:
                self._rotate()
        except OSError:
            # Reopen on the next sample, including after a failed rotation.
            previous, self.file = self.file, None
            if previous is not None:
                try:
                    previous.close()
                except OSError:
                    pass
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            if self.file is not None:
                self.file.close()
        finally:
            if self.lock_file is not None:
                self.lock_file.close()


class EventHook:
    """One child and one replaceable pending event, independent of sampling.

    Only single-threaded calls to submit() and close() are supported: both must
    be called from the same caller thread, as run_watch does.
    """

    def __init__(self, path):
        self.path = path
        self.thread = None
        self.lock = threading.Lock()
        self.running = False
        self.pending = None
        self.abandoned = False

    def submit(self, record):
        if not self.path or not {"warn", "recover"}.intersection(record["events"]):
            return
        # Snapshot now: callers may reuse/mutate the record while a hook runs.
        payload = (json.dumps(record) + "\n").encode()
        with self.lock:
            if self.abandoned:
                print("error: event hook disabled after unreaped child; skipping event", file=sys.stderr)
                return
            if self.running:
                action = "replacing pending event" if self.pending is not None else "queued latest event"
                self.pending = payload
                print("event hook still running; " + action, file=sys.stderr)
                return
            self.running = True
            self.thread = threading.Thread(target=self._drain, args=(payload,))
        self.thread.start()

    def _drain(self, payload):
        while True:
            completed = self._execute(payload)
            with self.lock:
                if not completed:
                    # A killed child may still exist. Do not start a second one.
                    self.abandoned = True
                    self.pending = None
                if self.pending is None:
                    self.running = False
                    return
                payload, self.pending = self.pending, None

    def _execute(self, payload):
        try:
            child = subprocess.Popen([str(self.path)], stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL, start_new_session=True)
            try:
                child.communicate(payload, timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                print("error: event hook timed out after 60 seconds; killed child", file=sys.stderr)
                try:
                    child.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    print("error: event hook reap timed out after 10 seconds; abandoning wait and disabling hooks",
                          file=sys.stderr)
                    return False
                return True
            if child.returncode:
                print("error: event hook exited %s" % child.returncode, file=sys.stderr)
        except (OSError, subprocess.SubprocessError) as exc:
            print("error: event hook failed (%s)" % exc.__class__.__name__, file=sys.stderr)
        return True

    def close(self):
        # Drain the latest pending event too; each child has bounded waits.
        if self.thread is not None:
            self.thread.join()


def run_watch(baseline_interval=900, elevated_interval=30, log=None, top=5,
              max_bytes=5_000_000, count=None, *, runner=None, fd_enumerator=None,
              wait=None, now=None, stop_event=None, stream=None, thresholds=None, on_event=None):
    """Emit one record immediately, then wait at the tier selected by each sample.

    Clock, wait, sysctls and fd enumeration can all be replaced in tests.
    Signal handlers only set an event, so an in-flight sample/write can finish.
    """
    if runner is None and platform.system() != "Darwin":
        print("error: panicsight watch requires macOS: sysctl kern.* names "
              "are unavailable on this platform", file=sys.stderr)
        return 2
    runner = runner if runner is not None else check.default_runner()
    fd_enumerator = fd_enumerator if fd_enumerator is not None else enumerate_fds
    now = now if now is not None else lambda: datetime.now().astimezone()
    stop_event = stop_event if stop_event is not None else threading.Event()
    wait = wait if wait is not None else stop_event.wait
    handlers = {}

    def stop(signum, frame):
        stop_event.set()

    state = TierState(thresholds)
    hook = EventHook(on_event)
    sampled = 0
    write_failed = False
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, stop)
        with RecordWriter(log, max_bytes, stream) as writer:
            try:
                while not stop_event.is_set():
                    sample = collect_sample(runner, fd_enumerator, top, now, thresholds)
                    events, triggers = state.update(sample)
                    interval = (elevated_interval if state.mode == "elevated"
                                else baseline_interval)
                    record = make_record(sample, state.mode, interval, events, triggers, thresholds)
                    try:
                        writer.write(record)
                    except OSError as exc:
                        if not write_failed:
                            print("error: log write failed (%s); retrying with next sample"
                                  % exc.__class__.__name__, file=sys.stderr)
                        write_failed = True
                    else:
                        if write_failed:
                            print("log write recovered", file=sys.stderr)
                        write_failed = False
                    hook.submit(record)
                    sampled += 1
                    if count is not None and sampled >= count:
                        break
                    if not stop_event.is_set():
                        wait(interval)
            except KeyboardInterrupt:
                pass
        return 0
    finally:
        hook.close()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
