import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from panicsight import watch


class Child:
    def __init__(self, timeout=False, code=0, gate=None):
        self.returncode = code
        self.timeout = timeout
        self.gate = gate
        self.calls = []
        self.killed = False

    def communicate(self, data=None, timeout=None):
        self.calls.append((data, timeout))
        if self.timeout and not self.killed:
            raise watch.subprocess.TimeoutExpired('fixture', 60)
        if self.gate:
            self.gate.wait(3)
        return None, None

    def kill(self):
        self.killed = True  # fake: no process and no OS signal


def test_hook_nonblocking_and_queued_recover(monkeypatch, capsys):
    gate, entered = threading.Event(), threading.Event()
    child = Child(gate=gate)
    recovered = Child()
    def popen(*args, **kwargs):
        entered.set()
        return child if factory.call_count == 1 else recovered
    factory = Mock(side_effect=popen)
    monkeypatch.setattr(watch.subprocess, 'Popen', factory)
    hook = watch.EventHook('/path with spaces/hook')
    try:
        hook.submit({'events': ['warn'], 'schema': 1})
        assert entered.wait(1)
        assert hook.thread.is_alive(), 'submit blocked until fake child finished'
        hook.submit({'events': ['recover']})
        assert factory.call_count == 1
        assert 'queued latest event' in capsys.readouterr().err
        assert hook.thread.is_alive()
    finally:
        gate.set()
        if hook.thread is not None and hook.thread.ident is not None:
            hook.close()
    assert factory.call_args.args == (['/path with spaces/hook'],)
    assert factory.call_args.kwargs['start_new_session'] is True
    assert json.loads(child.calls[0][0])['schema'] == 1
    assert child.calls[0][1] == 60
    assert factory.call_count == 2
    assert json.loads(recovered.calls[0][0])['events'] == ['recover']
    assert not hook.thread.is_alive()


def test_hook_only_runs_latest_pending_event(monkeypatch, capsys):
    gate, entered = threading.Event(), threading.Event()
    first, last = Child(gate=gate), Child()
    def popen(*args, **kwargs):
        entered.set()
        if factory.call_count == 2:
            assert gate.is_set(), 'second child started while first child was running'
        return first if factory.call_count == 1 else last
    factory = Mock(side_effect=popen)
    monkeypatch.setattr(watch.subprocess, 'Popen', factory)
    hook = watch.EventHook('/fixture')
    try:
        hook.submit({'events': ['warn'], 'ts': 'first'})
        assert entered.wait(1)
        hook.submit({'events': ['recover'], 'ts': 'superseded'})
        latest = {'events': ['warn'], 'ts': 'latest'}
        hook.submit(latest)
        latest['ts'] = 'mutated by caller'
        assert factory.call_count == 1
        assert 'replacing pending event' in capsys.readouterr().err
    finally:
        gate.set()
        hook.close()
    assert factory.call_count == 2
    assert json.loads(last.calls[0][0]) == {'events': ['warn'], 'ts': 'latest'}


def test_timeout_kills_and_reaps_fake_child(monkeypatch, capsys):
    child = Child(timeout=True)
    monkeypatch.setattr(watch.subprocess, 'Popen', lambda *a, **k: child)
    hook = watch.EventHook('/fixture'); hook.submit({'events': ['warn']}); hook.close()
    assert child.killed and len(child.calls) == 2 and child.calls[-1] == (None, 10)
    assert 'timed out after 60 seconds; killed child' in capsys.readouterr().err


def test_reap_timeout_abandons_wait_and_does_not_start_another_child(monkeypatch, capsys):
    gate, entered = threading.Event(), threading.Event()
    child = Child()
    def communicate(data=None, timeout=None):
        child.calls.append((data, timeout))
        entered.set()
        gate.wait(3)
        # A missing timeout would hang a real reap; require the exact upper bounds.
        assert timeout == (10 if child.killed else 60)
        raise watch.subprocess.TimeoutExpired('fixture', timeout)
    child.communicate = communicate
    factory = Mock(return_value=child)
    monkeypatch.setattr(watch.subprocess, 'Popen', factory)
    hook = watch.EventHook('/fixture')
    try:
        hook.submit({'events': ['warn']})
        assert entered.wait(1)
        hook.submit({'events': ['recover']})
    finally:
        gate.set()
        hook.close()
    assert child.killed and [c[1] for c in child.calls] == [60, 10]
    assert not hook.thread.is_alive()
    assert 'reap timed out after 10 seconds; abandoning wait' in capsys.readouterr().err
    hook.submit({'events': ['warn']})
    assert 'disabled after unreaped child' in capsys.readouterr().err
    assert factory.call_count == 1


@pytest.mark.parametrize('failure', ['exit', 'spawn'])
def test_hook_failure_does_not_stop_writing(tmp_path, monkeypatch, capsys, failure):
    def factory(*a, **k):
        if failure == 'spawn': raise OSError('fixture missing')
        return Child(code=7)
    monkeypatch.setattr(watch.subprocess, 'Popen', factory)
    path = tmp_path/'watch.jsonl'
    assert watch.run_watch(log=path, count=2, runner={'kern.num_files': 60, 'kern.maxfiles': 100}.get,
        fd_enumerator=lambda: [], wait=lambda _: None,
        now=lambda: datetime.now(timezone.utc), on_event='/fixture') == 0
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 2 and rows[0]['events'] == ['escalate', 'warn']
    assert ('exited 7' if failure == 'exit' else 'hook failed (OSError)') in capsys.readouterr().err


def test_hook_filters_events(monkeypatch):
    factory=Mock(); monkeypatch.setattr(watch.subprocess, 'Popen', factory)
    for path in (None, '/fixture'):
        hook=watch.EventHook(path); hook.submit({'events':['escalate']}); hook.close()
    factory.assert_not_called()
