import json


def build_header(os_version="Darwin 24.4.0", bug_type="210",
                 timestamp="2026-10-16 09:00:00.000 +0200"):
    return {
        "bug_type": bug_type,
        "os_version": os_version,
        "timestamp": timestamp,
    }


def make_thread(tid, state, wait_event=None):
    thread = {"tid": tid, "state": list(state)}
    if wait_event is not None:
        thread["waitEvent"] = list(wait_event)
    return thread


def make_proc(pid, procname, threads):
    return {"pid": pid, "procname": procname, "threadById": threads}


def launchd_sigbus_threads():
    threads = {}
    for tid in range(1, 512):
        threads[str(tid)] = make_thread(tid, ("TH_WAIT", "TH_UNINT"), (8, 3))
    threads["512"] = make_thread(512, ("TH_WAIT", "TH_UNINT"), (4, 9))
    threads["513"] = make_thread(513, ("TH_WAIT",))
    threads["514"] = make_thread(514, ("TH_WAIT",))
    threads["515"] = make_thread(515, ("TH_WAIT",))
    return threads


def launchd_sigbus_body(threads=None):
    return {
        "panicString": "panic(cpu 2 caller 0xfffffe003fc27c1c): "
                       "initproc exited -- exit reason namespace 2 subcode 0xa",
        "memoryStatus": {"memoryPressure": False},
        "processByPid": {
            "1234": make_proc(1234, "pagefind_extended",
                              threads or launchd_sigbus_threads()),
            "99": make_proc(99, "mds_stalled", {
                "1": make_thread(1, ("TH_WAIT", "TH_UNINT"), (22, 7)),
                "2": make_thread(2, ("TH_WAIT", "TH_UNINT"), (22, 7)),
                "3": make_thread(3, ("TH_WAIT", "TH_UNINT"), (22, 7)),
            }),
        },
        "binaryImages": [
            ["11E9F2C5-1A1E-3FEF-8CDB-0E3D3D5C2C63", "0xfffffe003fc00000", "P"],
        ],
    }


def watchdog_body():
    return {
        "panicString": "panic(cpu 0 caller 0xfffffe001c123456): "
                       "watchdog timeout: no checkins from watchdogd in 92 seconds",
        "memoryStatus": {"memoryPressure": True},
        "processByPid": {
            "0": make_proc(0, "kernel_task", {
                "100": make_thread(100, ("TH_WAIT", "TH_UNINT"), (3, 4)),
                "101": make_thread(101, ("TH_WAIT", "TH_UNINT"), (3, 4)),
            }),
        },
    }


def other_body(panic_string=None):
    if panic_string is None:
        panic_string = ("panic(cpu 3 caller 0xfffffe0000000000): Assertion failed "
                        "in file mach_vm.c line 42: reserved != 0. "
                        "This is a synthetic filler string used to push the length "
                        "of the panicString well beyond the 160 character excerpt "
                        "limit so the truncation behaviour can be verified here.")
    return {
        "panicString": panic_string,
        "memoryStatus": {"memoryPressure": False},
        "processByPid": {
            "55": make_proc(55, "spotlight_worker", {
                "7": make_thread(7, ("TH_WAIT",), (5, 6)),
            }),
        },
    }


def minimal_body():
    return {
        "panicString": "initproc exited -- exit reason namespace 2 subcode 0xa",
        "memoryStatus": {"memoryPressure": False},
    }


def write_panic(path, header=None, body=None):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(header or build_header()) + "\n")
        fh.write(json.dumps(body if body is not None else launchd_sigbus_body()))


def write_text(path, text="this file is not a panic report"):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)