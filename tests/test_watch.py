import ctypes
from datetime import datetime, timedelta, timezone
import io
import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")
sys.path.insert(0, SRC)
from panicsight import check, cli, watch  # noqa: E402


LOW = {"kern.num_files": 5, "kern.maxfiles": 100,
       "kern.maxfilesperproc": 80, "kern.num_vnodes": 90,
       "kern.maxvnodes": 100, "kern.free_vnodes": 40}
KEYS = {"schema", "ts", "mode", "next_interval_s", "events", "triggers", "num_files",
        "maxfiles", "maxfilesperproc", "num_vnodes", "maxvnodes", "free_vnodes",
        "file_table_pct", "free_vnode_pct", "status", "warnings", "thresholds", "top_fd"}


@pytest.fixture(autouse=True)
def fake_default_sysctls(monkeypatch):
    # Unit tests, including CLI defaults, cannot invoke a real sysctl subprocess.
    monkeypatch.setattr(check, "default_runner", lambda: LOW.get)
    monkeypatch.setattr(watch.platform, "system", lambda: "Darwin")


class FakeClock:
    def __init__(self):
        self.t = 0
        self.waits = []

    def wait(self, seconds):
        self.waits.append(seconds)
        self.t += seconds

    def now(self):
        return datetime(2026, 10, 16, 12, tzinfo=timezone(timedelta(hours=-7))) + timedelta(seconds=self.t)


class Sampling:
    def __init__(self, values, holders=None):
        self.values = values
        self.holders = holders
        self.index = -1
        self.calls = []

    def runner(self, name):
        self.calls.append(name)
        if name == check.SYSCTL_NAMES[0]:
            self.index += 1
        return self.values[self.index].get(name)

    def fds(self):
        if self.holders is not None:
            return self.holders[self.index]
        return [{"pid": self.index + 10, "name": "worker-%d" % self.index,
                 "fds": (self.index + 1) * 10}]


def run_samples(tmp_path, values, holders=None, **kwargs):
    clock = FakeClock()
    sampling = Sampling(values, holders)
    path = tmp_path / "nested" / "watch.jsonl"
    code = watch.run_watch(
        log=path, count=len(values), runner=sampling.runner, fd_enumerator=sampling.fds,
        wait=clock.wait, now=clock.now, **kwargs)
    return code, [json.loads(line) for line in path.read_text().splitlines()], clock, sampling


def value(num_files=5, free_vnodes=40):
    return dict(LOW, **{"kern.num_files": num_files, "kern.free_vnodes": free_vnodes})


def test_one_record_per_sample_immediate_start_and_shared_collect_evaluate(tmp_path, monkeypatch):
    collect = Mock(wraps=check.collect_values)
    evaluate = Mock(wraps=check.evaluate)
    monkeypatch.setattr(check, "collect_values", collect)
    monkeypatch.setattr(check, "evaluate", evaluate)
    code, rows, clock, sampling = run_samples(tmp_path, [LOW, LOW, LOW])
    assert code == 0
    assert len(rows) == 3
    assert [row["top_fd"][0]["pid"] for row in rows] == [10, 11, 12]
    assert sampling.calls == list(check.SYSCTL_NAMES) * 3
    assert collect.call_count == evaluate.call_count == 3
    assert clock.waits == [900, 900]
    assert [datetime.fromisoformat(row["ts"]) for row in rows] == [
        clock.now() - timedelta(seconds=s) for s in (1800, 900, 0)]


@pytest.mark.parametrize("values,trigger", [
    ([value(20)], "file_table_pct>=20"),
    ([value(free_vnodes=30)], "free_vnode_pct<=30"),
    ([value(5), value(10)], "growth>=5pp"),
    ([value(15)], "status=WARN"),
])
def test_each_trigger_alone_escalates(tmp_path, monkeypatch, values, trigger):
    if trigger == "status=WARN":
        # Normally WARN is a subset of elevated thresholds; lower only WARN to isolate it.
        monkeypatch.setattr(check, "FILE_TABLE_WARN_PCT", 15.0)
    _, rows, clock, _ = run_samples(tmp_path, values)
    assert rows[-1]["triggers"] == [trigger]
    assert rows[-1]["mode"] == "elevated"
    assert rows[-1]["next_interval_s"] == 30
    assert rows[-1]["events"] == (["escalate", "warn"] if trigger == "status=WARN" else ["escalate"])
    assert clock.waits == ([900] if len(values) == 2 else [])


def test_just_inside_thresholds_does_not_trigger(tmp_path):
    _, rows, _, _ = run_samples(tmp_path, [value(15, 31), value(19, 31)])
    assert [row["triggers"] for row in rows] == [[], []]
    assert [row["mode"] for row in rows] == ["baseline", "baseline"]


def test_null_values_never_trigger_and_break_growth_chain(tmp_path):
    _, rows, _, _ = run_samples(tmp_path, [value(1), {}, value(19), {}])
    for row in rows:
        assert row["mode"] == "baseline"
        assert row["triggers"] == row["events"] == row["warnings"] == []
        assert row["status"] == "OK"
    for row in (rows[1], rows[3]):
        for key in ("num_files", "maxfiles", "maxfilesperproc", "num_vnodes",
                    "maxvnodes", "free_vnodes", "file_table_pct", "free_vnode_pct"):
            assert row[key] is None


def test_growth_compares_only_immediately_previous_sample(tmp_path):
    _, rows, _, _ = run_samples(tmp_path, [value(n) for n in (1, 4, 7, 3, 8, 9)])
    assert [row["triggers"] for row in rows] == [[], [], [], [], ["growth>=5pp"], []]
    assert [row["events"] for row in rows] == [[], [], [], [], ["escalate"], []]


def test_deescalates_exactly_after_ten_untriggered_samples(tmp_path):
    _, rows, clock, _ = run_samples(tmp_path, [value(20)] + [LOW] * 11,
                                   baseline_interval=901, elevated_interval=31)
    assert [row["mode"] for row in rows] == ["elevated"] * 10 + ["baseline"] * 2
    assert [row["next_interval_s"] for row in rows] == [31] * 10 + [901] * 2
    assert [row["events"] for row in rows] == [["escalate"]] + [[]] * 9 + [["deescalate"], []]
    assert clock.waits == [31] * 10 + [901]


def test_trigger_resets_deescalation_counter_and_can_escalate_again(tmp_path):
    values = [value(20)] + [LOW] * 9 + [value(free_vnodes=30)] + [LOW] * 10 + [value(20)]
    _, rows, _, _ = run_samples(tmp_path, values)
    assert all(row["mode"] == "elevated" for row in rows[:20])
    assert rows[10]["triggers"] == ["free_vnode_pct<=30"]
    assert rows[10]["events"] == []
    assert rows[20]["mode"] == "baseline"
    assert rows[20]["events"] == ["deescalate"]
    assert rows[21]["mode"] == "elevated"
    assert rows[21]["events"] == ["escalate"]


def test_warn_recover_and_first_sample_warn(tmp_path):
    _, rows, clock, _ = run_samples(tmp_path, [value(70), value(80), LOW, LOW, value(free_vnodes=1)])
    assert [row["events"] for row in rows] == [["escalate", "warn"], [], ["recover"], [], ["warn"]]
    assert rows[0]["triggers"] == ["file_table_pct>=20", "status=WARN"]
    assert rows[1]["triggers"] == ["file_table_pct>=20", "status=WARN", "growth>=5pp"]
    assert rows[0]["warnings"] == ["file table use is 70.0% of kern.maxfiles (>= 50%)"]
    assert rows[-1]["warnings"] == ["free vnodes are 1.0% of kern.maxvnodes (< 10%)"]
    assert rows[-1]["triggers"] == ["free_vnode_pct<=30", "status=WARN"]
    assert [row["status"] for row in rows] == ["WARN", "WARN", "OK", "OK", "WARN"]
    assert clock.waits == [30] * 4


def test_exact_schema_and_shared_thresholds(tmp_path, monkeypatch):
    monkeypatch.setattr(check, "FILE_TABLE_WARN_PCT", 80.0)
    monkeypatch.setattr(check, "FREE_VNODE_WARN_PCT", 5.0)
    monkeypatch.setattr(check, "ELEVATED_FILE_TABLE_PCT", 60.0)
    monkeypatch.setattr(check, "ELEVATED_FREE_VNODE_PCT", 6.0)
    monkeypatch.setattr(check, "GROWTH_PCT_POINTS", 8.0)
    monkeypatch.setattr(check, "DEESCALATE_AFTER_SAMPLES", 2)
    _, rows, _, _ = run_samples(tmp_path, [value(61, 5), LOW, LOW])
    row = rows[0]
    assert set(row) == KEYS | set(check.PRESSURE_FIELDS)
    assert row["schema"] == 1
    assert row["status"] == "OK"
    assert row["warnings"] == []
    assert row["triggers"] == ["file_table_pct>=60", "free_vnode_pct<=6"]
    assert row["thresholds"] == {"file_table_warn_pct": 80.0, "free_vnode_warn_pct": 5.0,
                                 "file_table_elevated_pct": 60.0, "free_vnode_elevated_pct": 6.0,
                                 "growth_pct_points": 8.0, **check.PRESSURE_DEFAULTS}
    assert rows[2]["events"] == ["deescalate"]
    assert set(row["top_fd"][0]) == {"pid", "name", "fds"}
    assert datetime.fromisoformat(row["ts"]).utcoffset() is not None
    assert datetime.fromisoformat(row["ts"]).microsecond == 0
    assert type(row["next_interval_s"]) is int


def test_rank_limit_and_names_only(tmp_path):
    holders = [[{"pid": 3, "name": "tiny", "fds": 3},
                {"pid": 2, "name": "/private/project/busy", "fds": 400,
                 "argv": "secret arguments", "cwd": "/private/project"},
                {"pid": 1, "name": "/Users/person/other", "fds": 400}]]
    _, rows, _, _ = run_samples(tmp_path, [LOW], holders, top=2)
    assert rows[0]["top_fd"] == [{"pid": 1, "name": "other", "fds": 400},
                                 {"pid": 2, "name": "busy", "fds": 400}]


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_signal_stops_wait_without_extra_record_and_restores_handlers(tmp_path, signum):
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    path = tmp_path / "signal.jsonl"
    waits = []

    def wait(seconds):
        waits.append(seconds)
        os.kill(os.getpid(), signum)

    assert watch.run_watch(log=path, fd_enumerator=lambda: [], wait=wait) == 0
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["mode"] == "baseline"
    assert waits == [900]
    assert {sig: signal.getsignal(sig) for sig in before} == before


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_prompt_signal_exit_during_real_long_wait(tmp_path, signum):
    # A separate process exercises real signal delivery + Event.wait, with fake probes.
    ready = tmp_path / "waiting"
    path = tmp_path / "signal.jsonl"
    script = '''
import sys, threading
from pathlib import Path
from panicsight.watch import run_watch
stop = threading.Event()
def wait(seconds):
    assert seconds == 900
    Path(sys.argv[2]).write_text("waiting")
    return stop.wait(seconds)
raise SystemExit(run_watch(log=sys.argv[1], runner=lambda name: None,
                          fd_enumerator=lambda: [], stop_event=stop, wait=wait))
'''
    env = dict(os.environ, PYTHONPATH=SRC)
    proc = subprocess.Popen([sys.executable, "-c", script, str(path), str(ready)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), "child did not reach its 900s wait"
        start = time.monotonic()
        proc.send_signal(signum)
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, err.decode()
        assert time.monotonic() - start < 5
        assert out == err == b""
        assert len(path.read_text().splitlines()) == 1
    finally:
        if proc.poll() is None:
            proc.kill()  # Only the child PID created by this test.
            proc.communicate()


def test_keyboard_interrupt_exits_zero_without_extra_record():
    out = io.StringIO()

    def wait(seconds):
        raise KeyboardInterrupt

    assert watch.run_watch(stream=out, fd_enumerator=lambda: [], wait=wait) == 0
    assert len(out.getvalue().splitlines()) == 1
    assert "baseline OK next=900s" in out.getvalue()


def test_stop_before_first_sample_has_no_record():
    stop = threading.Event()
    stop.set()
    out = io.StringIO()
    assert watch.run_watch(stream=out, stop_event=stop) == 0
    assert out.getvalue() == ""


def test_stop_during_sample_finishes_record_without_wait():
    stop = threading.Event()
    out = io.StringIO()
    wait = Mock()

    def fds():
        stop.set()
        return []

    assert watch.run_watch(stream=out, fd_enumerator=fds, stop_event=stop, wait=wait) == 0
    assert len(out.getvalue().splitlines()) == 1
    assert "baseline OK" in out.getvalue()
    wait.assert_not_called()


def test_default_event_wait_and_default_enumerator(monkeypatch):
    stop = Mock()
    stop.is_set.side_effect = [False, False, True]
    monkeypatch.setattr(watch, "enumerate_fds", lambda: [])
    out = io.StringIO()
    assert watch.run_watch(stop_event=stop, stream=out) == 0
    stop.wait.assert_called_once_with(900)
    assert len(out.getvalue().splitlines()) == 1


def test_write_failure_streaks_keep_sampling_and_recover(monkeypatch, capsys):
    clock = FakeClock()
    sampling = Sampling([value(5), value(20), LOW, LOW, LOW, LOW, LOW])
    writer = Mock()
    writer.__enter__ = Mock(return_value=writer)
    writer.__exit__ = Mock(return_value=False)
    writer.write.side_effect = [OSError("full"), OSError("full"), None, None,
                                OSError("offline"), OSError("offline"), None]
    monkeypatch.setattr(watch, "RecordWriter", Mock(return_value=writer))
    assert watch.run_watch(count=7, runner=sampling.runner, fd_enumerator=sampling.fds,
                           wait=clock.wait, now=clock.now) == 0
    rows = [call.args[0] for call in writer.write.call_args_list]
    assert [row["top_fd"][0]["pid"] for row in rows] == list(range(10, 17))
    assert sampling.calls == list(check.SYSCTL_NAMES) * 7
    assert clock.waits == [900] + [30] * 5
    assert [row["mode"] for row in rows] == ["baseline"] + ["elevated"] * 6
    assert [row["ts"] for row in rows] == [
        (datetime(2026, 10, 16, 12, tzinfo=timezone(timedelta(hours=-7)))
         + timedelta(seconds=s)).isoformat(timespec="seconds")
        for s in (0, 900, 930, 960, 990, 1020, 1050)]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "error: log write failed (OSError); retrying with next sample",
        "log write recovered",
        "error: log write failed (OSError); retrying with next sample",
        "log write recovered"]
    writer.__exit__.assert_called_once_with(None, None, None)


def test_count_includes_failed_writes(monkeypatch, capsys):
    clock = FakeClock()
    target = Mock()
    target.write.side_effect = OSError("full")
    assert watch.run_watch(count=3, runner=LOW.get, fd_enumerator=lambda: [],
                           stream=target, wait=clock.wait) == 0
    assert target.write.call_count == 3
    assert clock.waits == [900, 900]
    assert capsys.readouterr().err == (
        "error: log write failed (OSError); retrying with next sample\n")


def record():
    sample = watch.collect_sample(LOW.get, lambda: [{"pid": 1, "name": "worker\nname", "fds": 3}],
                                  5, FakeClock().now)
    return watch.make_record(sample, "baseline", 900, [], [])


def test_single_write_then_flush_for_each_text_line():
    target = Mock()
    row = record()
    row["warnings"] = ["test warning"]
    with watch.RecordWriter(stream=target) as writer:
        writer.write(row)
    assert [c[0] for c in target.method_calls] == ["write", "flush"]
    line = target.write.call_args.args[0]
    assert line.endswith("\n")
    assert len(line.splitlines()) == 1
    assert "warnings=test warning" in line
    assert '"worker\\nname" (pid 1): 3' in line


def test_text_null_percentages():
    sample = watch.collect_sample(lambda name: None, lambda: [], 5, FakeClock().now)
    line = watch.render_text(watch.make_record(sample, "baseline", 900, [], []))
    assert "file_table=unknown free_vnodes=unknown top_fd=[none]" in line


def test_log_write_is_single_full_json_line(tmp_path):
    row = record()
    with watch.RecordWriter(tmp_path / "write.jsonl") as writer:
        target = Mock(wraps=writer.file)
        target.tell.side_effect = writer.file.tell
        writer.file = target
        writer.write(row)
        assert [c[0] for c in target.method_calls] == ["write", "flush", "tell"]
        line = target.write.call_args.args[0]
        assert line.endswith("\n")
        assert len(line.splitlines()) == 1
        assert json.loads(line) == row


def test_rotation_after_limit_replaces_only_backup(tmp_path):
    path = tmp_path / "log.jsonl"
    backup = tmp_path / "log.jsonl.1"
    path.write_text("")
    backup.write_text("old backup")
    with watch.RecordWriter(path, max_bytes=8) as writer:
        writer.write({"n": 1})  # Exactly 8 bytes: do not rotate yet.
        assert path.read_text() == '{"n":1}\n'
        assert backup.read_text() == "old backup"
        writer.write({"n": 2})
        assert path.read_text() == ""
        assert backup.read_text() == '{"n":1}\n{"n":2}\n'
        writer.write({"n": 3})
        writer.write({"n": 4})
        assert backup.read_text() == '{"n":3}\n{"n":4}\n'
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "log.jsonl", "log.jsonl.1", "log.jsonl.lock"]


def test_append_existing_and_rotate_oversized_on_open(tmp_path):
    path = tmp_path / "existing.jsonl"
    path.write_text('{"old":1}\n')
    with watch.RecordWriter(path) as writer:
        writer.write({"new": 2})
    assert path.read_text() == '{"old":1}\n{"new":2}\n'
    with watch.RecordWriter(path, max_bytes=10):
        assert path.read_text() == ""
        assert path.with_name(path.name + ".1").read_text() == '{"old":1}\n{"new":2}\n'


def test_rotation_failure_reopens_and_recovers_next_record(tmp_path, monkeypatch, capsys):
    path = tmp_path / "rotate.jsonl"
    replace = Path.replace
    attempts = []

    def fail_twice(source, target):
        attempts.append(source)
        if len(attempts) <= 2:
            raise PermissionError("rotation unavailable")
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_twice)
    assert watch.run_watch(log=path, max_bytes=1, count=3, runner=LOW.get,
                           fd_enumerator=lambda: [], wait=lambda seconds: None) == 0
    assert attempts == [path] * 3
    assert path.read_text() == ""
    rows = [json.loads(line) for line in Path(str(path) + ".1").read_text().splitlines()]
    assert len(rows) == 3
    assert all(set(row) == KEYS | set(check.PRESSURE_FIELDS) for row in rows)
    assert capsys.readouterr().err.splitlines() == [
        "error: log write failed (PermissionError); retrying with next sample",
        "log write recovered"]


@pytest.mark.parametrize("phase", ["write", "flush", "reopen"])
def test_writer_recovers_file_errors_without_losing_lock(tmp_path, monkeypatch, phase):
    path = tmp_path / "retry.jsonl"
    with watch.RecordWriter(path) as writer:
        original = writer.file
        with monkeypatch.context() as patch:
            if phase == "reopen":
                writer.max_bytes = 1
                path_open = Path.open

                def fail_reopen(target, *args, **kwargs):
                    if target == path:
                        raise OSError("temporarily unavailable")
                    return path_open(target, *args, **kwargs)

                patch.setattr(Path, "open", fail_reopen)
            else:
                writer.file = Mock(wraps=original)
                getattr(writer.file, phase).side_effect = OSError("temporarily unavailable")
            with pytest.raises(OSError, match="temporarily unavailable"):
                writer.write({"n": 1})
        assert original.closed
        assert writer.file is None
        with pytest.raises(watch.LogLockedError, match="another panicsight watch"):
            with watch.RecordWriter(path):
                pytest.fail("second writer acquired the log during a write failure")
        writer.max_bytes = 5_000_000
        writer.write({"n": 2})
    assert json.loads(path.read_text().splitlines()[-1]) == {"n": 2}


def test_log_lock_blocks_second_writer_before_and_after_rotation(tmp_path, capsys):
    path = tmp_path / "locked.jsonl"
    backup = Path(str(path) + ".1")
    with watch.RecordWriter(path, max_bytes=1) as writer:
        lock_inode = Path(str(path) + ".lock").stat().st_ino
        for rotated in (False, True):
            if rotated:
                writer.write({"n": 1})
                assert backup.read_text() == '{"n":1}\n'
            assert cli.main(["watch", "--log", str(path), "--count", "1"]) == 2
            assert capsys.readouterr().err == (
                "error: another panicsight watch is already writing %s\n" % path)
            assert path.read_text() == ""
            assert Path(str(path) + ".lock").stat().st_ino == lock_inode
    # Keep the lock file on disk: unlinking it could let writers lock different inodes.
    with watch.RecordWriter(path) as writer:
        writer.write({"n": 2})
    assert path.read_text() == '{"n":2}\n'
    assert backup.read_text() == '{"n":1}\n'


def test_startup_open_failure_releases_lock(tmp_path, monkeypatch, capsys):
    path = tmp_path / "blocked.jsonl"
    path_open = Path.open

    def fail_log_open(target, *args, **kwargs):
        if target == path:
            raise PermissionError("blocked")
        return path_open(target, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", fail_log_open)
        assert cli.main(["watch", "--log", str(path), "--count", "1"]) == 2
    assert capsys.readouterr().err == "error: cannot write watch output (PermissionError)\n"
    with watch.RecordWriter(path) as writer:
        writer.write({"n": 1})
    assert path.read_text() == '{"n":1}\n'


def test_non_macos_enumerator_returns_empty_without_loading(monkeypatch):
    loader = Mock(side_effect=AssertionError("must not load libproc on Linux"))
    monkeypatch.setattr(watch.platform, "system", lambda: "Linux")
    monkeypatch.setattr(watch.ctypes, "CDLL", loader)
    assert watch.enumerate_fds() == []
    loader.assert_not_called()


@pytest.mark.parametrize("error", [OSError("unavailable"), AttributeError("no symbol")])
def test_unavailable_libproc_returns_empty(monkeypatch, error):
    monkeypatch.setattr(watch.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(watch.ctypes, "CDLL", Mock(side_effect=error))
    assert watch.enumerate_fds() == []


def fake_libproc(monkeypatch, pids, sizes=None, names=None, needed=None, found=None,
                 copied=None):
    copies = {pid: iter(values) for pid, values in (copied or {}).items()}

    def listpids(buffer, byte_size):
        if buffer is None:
            assert byte_size == 0
            return len(pids) if needed is None else needed
        for i, pid in enumerate(pids):
            buffer[i] = pid
        return len(pids) if found is None else found

    def pidinfo(pid, flavor, arg, buffer, byte_size):
        assert (flavor, arg) == (1, 0)
        if buffer is None:
            assert byte_size == 0
            return sizes[pid]
        assert ctypes.sizeof(buffer) == byte_size
        returned = next(copies[pid]) if pid in copies else sizes[pid] - 8
        if returned > 0:
            assert returned <= byte_size
            assert returned % 8 == 0
            ctypes.memset(buffer, 0, returned)
        return returned

    def name(pid, buffer, byte_size):
        val = names[pid]
        buffer.value = val
        return len(val)

    lib = Mock()
    lib.proc_listallpids.side_effect = listpids
    lib.proc_pidinfo.side_effect = pidinfo
    lib.proc_name.side_effect = name
    monkeypatch.setattr(watch.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(watch.ctypes, "CDLL", lambda path: lib)
    return lib


def test_ctypes_counts_skip_inaccessible_and_missing_names(monkeypatch):
    lib = fake_libproc(monkeypatch, [0, -1, 10, 11, 12, 13, 14],
                      {10: 0, 11: 24, 12: 80, 13: -1, 14: 16},
                      {11: b"", 12: b"/some/worker", 14: b"/"},
                      copied={11: [16], 12: [32], 14: [8]})
    assert ctypes.sizeof(watch.ProcFdInfo) == 8
    assert watch.enumerate_fds() == [{"pid": 12, "name": "worker", "fds": 4}]
    assert lib.proc_pidinfo.call_count == 8
    assert lib.proc_name.call_count == 3
    assert lib.proc_pidinfo.argtypes[2] is ctypes.c_uint64


@pytest.mark.parametrize("copied,expected,buffer_sizes", [
    ([24], 3, [80]),
    ([80, 104], 13, [80, 160]),
    ([80, 160], 20, [80, 160]),
    ([0], None, [80]),
    ([-1], None, [80]),
    ([80, 0], None, [80, 160]),
    ([80, -1], None, [80, 160]),
])
def test_ctypes_uses_copied_bytes_and_retries_full_buffer_once(
        monkeypatch, copied, expected, buffer_sizes):
    lib = fake_libproc(monkeypatch, [42], {42: 80}, {42: b"worker"},
                      copied={42: copied})
    assert watch.enumerate_fds() == (
        [] if expected is None else [{"pid": 42, "name": "worker", "fds": expected}])
    calls = lib.proc_pidinfo.call_args_list
    assert calls[0].args == (42, 1, 0, None, 0)
    assert [call.args[4] for call in calls[1:]] == buffer_sizes
    assert all(call.args[3] is not None for call in calls[1:])


@pytest.mark.parametrize("needed,found", [(0, None), (-1, None), (1, -1), (1, 100)])
def test_pid_listing_failure_and_bounds(monkeypatch, needed, found):
    fake_libproc(monkeypatch, [0], needed=needed, found=found)
    assert watch.enumerate_fds() == []


@pytest.mark.skipif(platform.system() != "Darwin", reason="real libproc requires macOS")
def test_real_darwin_libproc_smoke(tmp_path):
    pid = os.getpid()

    def current():
        return next(item for item in watch.enumerate_fds() if item["pid"] == pid)

    # Keep lsof's output fd open in both measurements, avoiding transient capture pipes.
    with (tmp_path / "lsof.txt").open("w+") as output:
        def compare_lsof(count):
            if Path("/usr/sbin/lsof").exists():
                output.seek(0)
                output.truncate()
                subprocess.run(["/usr/sbin/lsof", "-Fn", "-p", str(pid)],
                               stdout=output, check=True, timeout=10)
                output.seek(0)
                numbered = [line for line in output.read().splitlines()
                            if line.startswith("f") and line[1:].isdigit()]
                assert len(numbered) == count

        baseline = current()
        assert baseline["fds"] >= 3
        assert baseline["name"]
        compare_lsof(baseline["fds"])
        extra = []
        try:
            for _ in range(37):
                extra.append(os.open(os.devnull, os.O_RDONLY))
            raised = current()
            assert raised["fds"] - baseline["fds"] == 37
            compare_lsof(raised["fds"])
        finally:
            for fd in extra:
                os.close(fd)
        assert current()["fds"] == baseline["fds"]


def test_watch_non_macos_exits_two_before_probes_or_log_open(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(watch.platform, "system", lambda: "Linux")
    probe = Mock(side_effect=AssertionError("must not probe"))
    monkeypatch.setattr(check, "default_runner", probe)
    monkeypatch.setattr(watch, "enumerate_fds", probe)
    path = tmp_path / "absent" / "watch.jsonl"
    assert cli.main(["watch", "--log", str(path), "--count", "1"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ("error: panicsight watch requires macOS: sysctl kern.* names "
                            "are unavailable on this platform\n")
    probe.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_watch_injected_runner_works_on_non_macos(monkeypatch):
    monkeypatch.setattr(watch.platform, "system", lambda: "Linux")
    output = io.StringIO()
    assert watch.run_watch(runner=LOW.get, fd_enumerator=lambda: [], count=1,
                           stream=output) == 0
    assert "baseline OK" in output.getvalue()


def test_watch_cli_defaults_and_options(monkeypatch):
    run = Mock(return_value=0)
    monkeypatch.setattr(watch, "run_watch", run)
    assert cli.main(["watch"]) == 0
    assert run.call_args.kwargs == {"baseline_interval": 900, "elevated_interval": 30,
                                  "log": None, "top": 5, "max_bytes": 5_000_000, "count": None, "on_event": None, "thresholds": check.PRESSURE_DEFAULTS}
    assert cli.main(["watch", "--baseline-interval", "5", "--elevated-interval", "1",
                     "--log", "log.jsonl", "--top", "2", "--max-bytes", "1234", "--count", "3"]) == 0
    assert run.call_args.kwargs == {"baseline_interval": 5, "elevated_interval": 1,
                                  "log": "log.jsonl", "top": 2, "max_bytes": 1234, "count": 3, "on_event": None, "thresholds": check.PRESSURE_DEFAULTS}


@pytest.mark.parametrize("option,value", [
    ("--baseline-interval", "0"), ("--baseline-interval", "1.5"),
    ("--baseline-interval", "nan"), ("--baseline-interval", "inf"),
    ("--elevated-interval", "0"), ("--elevated-interval", "-1"),
    ("--elevated-interval", "1.5"), ("--elevated-interval", "x"),
    ("--top", "0"), ("--count", "-1"), ("--max-bytes", "0"),
])
def test_watch_cli_rejects_invalid_options(option, value, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["watch", option, value])
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_watch_cli_rejects_elevated_longer_than_baseline(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["watch", "--baseline-interval", "29"])
    assert exc.value.code == 2
    assert "--elevated-interval must be <= --baseline-interval" in capsys.readouterr().err


def test_watch_cli_count_runs_real_loop_without_real_sysctls(monkeypatch, capsys):
    clock = FakeClock()
    monkeypatch.setattr(watch.threading, "Event", lambda: Mock(is_set=lambda: False, wait=clock.wait))
    monkeypatch.setattr(watch, "enumerate_fds", lambda: [])
    assert cli.main(["watch", "--baseline-interval", "1", "--elevated-interval", "1", "--count", "3"]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    assert len(out.out.splitlines()) == 3
    assert clock.waits == [1, 1]


def test_watch_cli_write_failure_is_concise(monkeypatch, capsys):
    monkeypatch.setattr(watch, "run_watch", Mock(side_effect=PermissionError("private path")))
    assert cli.main(["watch", "--log", "blocked"]) == 2
    assert capsys.readouterr().err == "error: cannot write watch output (PermissionError)\n"
