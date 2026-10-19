import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from panicsight import check, cli, watch


def values(load=0, swap=0, level=80):
    return {'vm.loadavg': [load, load, 0], 'hw.logicalcpu': 1,
            'hw.memsize': 100 * 1024**3,
            'vm.swapusage': {'used': swap * 1024**3, 'total': 50 * 1024**3},
            'kern.memorystatus_level': level}


def sample(load=0, swap=0, level=80, **changes):
    result = check.evaluate(values(load, swap, level))
    result.update(changes)
    return result


@pytest.mark.parametrize('text,used,total', [
    ('total = 51200.00M used = 2048.50M free = 1M', 2048.5 * 1024**2, 50 * 1024**3),
    ('total = 50G used = 2.5G free = 47.5G', 2.5 * 1024**3, 50 * 1024**3)])
def test_swap_units(text, used, total):
    assert check.parse_sysctl('vm.swapusage', text) == {'used': int(used), 'total': int(total)}


@pytest.mark.parametrize('name,text,expected', [
    ('vm.loadavg', '{ 1.5 3.0 4.0 }', [1.5, 3, 4]),
    ('hw.logicalcpu', '18\n', 18), ('hw.memsize', '137438953472', 137438953472),
    ('vm.loadavg', '{ nan 1 2 }', None), ('vm.loadavg', '{ 1 2 }', None),
    ('vm.swapusage', 'used = 2M', None), ('hw.memsize', 'broken', None)])
def test_parse(name, text, expected):
    assert check.parse_sysctl(name, text) == expected


def test_real_runner_read_failures(monkeypatch):
    def fail(*a, **k):
        raise OSError('fixture')
    monkeypatch.setattr(check.subprocess, 'run', fail)
    assert all(v is None for v in check.collect_values(check.default_runner()).values())
    monkeypatch.setattr(check.subprocess, 'run', lambda *a, **k: Mock(returncode=1))
    assert check.default_runner()('hw.memsize') is None
    monkeypatch.setattr(check.subprocess, 'run', lambda *a, **k: Mock(returncode=0, stdout='{ 18 36 0 }'))
    assert check.default_runner()('vm.loadavg') == [18, 36, 0]


def test_normalization_and_missing():
    v = values(18, 25, 38); v['hw.logicalcpu'] = 18
    s = check.evaluate(v)
    assert s['load1_per_core'] == s['load5_per_core'] == 1
    assert s['swap_used_pct_of_ram'] == 25
    assert s['memorystatus_level'] == 38
    empty = check.evaluate({})
    assert all(empty[k] is None for k in check.PRESSURE_FIELDS)
    assert empty['status'] == 'OK'


@pytest.mark.parametrize('load,swap,level,warn', [
    (3, 0, 80, True), (2.999, 0, 80, False), (0, 25, 40, True),
    (0, 24.999, 40, False), (0, 25, 40.001, False), (0, 45, 77, False)])
def test_warn_boundaries(load, swap, level, warn):
    s = sample(load, swap, level)
    assert (s['status'] == 'WARN') is warn
    assert bool(s['warnings']) is warn


@pytest.mark.parametrize('load,trigger', [(1.5, True), (1.499, False)])
def test_elevated_load_boundary(load, trigger):
    events, triggers = watch.TierState().update(sample(load))
    assert ('load1_per_core>=1.5' in triggers) is trigger
    assert ('escalate' in events) is trigger


@pytest.mark.parametrize('growth,trigger', [(2, True), (1.999, False)])
def test_swap_growth_boundary(growth, trigger):
    state = watch.TierState()
    assert state.update(sample(swap=4))[1] == []
    assert ('swap_growth_bytes>=2.14748e+09' in state.update(sample(swap=4+growth))[1]) is trigger
    state.update(check.evaluate({}))
    assert state.update(sample(swap=40))[1] == []


def test_load_hysteresis_and_overlap():
    state = watch.TierState()
    s = sample(3); assert 'warn' in state.update(s)[0]
    for n in (2.999, 2.5, 2.0):
        s = sample(n); assert 'recover' not in state.update(s)[0]; assert s['status'] == 'WARN'
    s = sample(1.999, file_table_pct=60, warnings=['file fixture'], status='WARN')
    assert 'recover' not in state.update(s)[0]
    assert s['warnings'] == ['file fixture']
    s = sample(0); assert state.update(s)[0] == ['recover']
    assert s['status'] == 'OK'


@pytest.mark.parametrize('swap,level,recover', [(25, 50, False), (20, 45, False),
    (19.999, 45, True), (30, 50.001, True)])
def test_memory_hysteresis(swap, level, recover):
    state = watch.TierState()
    assert 'warn' in state.update(sample(swap=25, level=40))[0]
    s = sample(swap=swap, level=level)
    assert ('recover' in state.update(s)[0]) is recover
    assert (s['status'] == 'OK') is recover


def test_unknown_values_never_hold_or_trigger_warn():
    state = watch.TierState(); state.update(sample(3, 30, 38))
    s = check.evaluate({}); assert 'recover' in state.update(s)[0]
    assert s['warnings'] == []


def test_cli_threshold_options_and_record(tmp_path):
    argv = ['watch', '--on-event', '/fixture/hook']
    for k, v in check.PRESSURE_DEFAULTS.items():
        argv += ['--' + k.replace('_', '-'), str(v + 1)]
    args = cli.build_parser().parse_args(argv)
    t = {k: getattr(args, k) for k in check.PRESSURE_DEFAULTS}
    assert t == {k: v+1 for k, v in check.PRESSURE_DEFAULTS.items()}
    s = sample(2); s.update(ts='fixture', top_fd=[])
    record = watch.make_record(s, 'elevated', 30, [], [], t)
    assert record['schema'] == 1
    assert all(record['thresholds'][k] == v+1 for k, v in check.PRESSURE_DEFAULTS.items())
    assert all(k in record for k in check.PRESSURE_FIELDS)
    assert check.evaluate(values(3), dict(check.PRESSURE_DEFAULTS, load_warn_per_core=4))['status'] == 'OK'


def test_warning_prefix_names_its_category():
    """Consumers classify warnings by prefix; keep the field name first."""
    from panicsight.check import pressure_warnings
    sample = {"load5_per_core": 5.0, "swap_used_pct_of_ram": 30.0, "memorystatus_level": 20}
    warnings, current = pressure_warnings(sample)
    assert current == {"load", "memory"}
    assert [w.split("=", 1)[0] for w in warnings] == ["load5_per_core", "swap_used_pct_of_ram"]
    held, _ = pressure_warnings({"load5_per_core": 0.1, "swap_used_pct_of_ram": 22.0,
                                 "memorystatus_level": 45}, active={"memory"})
    assert len(held) == 1 and held[0].startswith("swap_used_pct_of_ram=")
