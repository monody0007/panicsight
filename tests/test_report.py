import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from panicsight import report  # noqa: E402

import make_fixtures as fx  # noqa: E402


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, header=None, body=None):
        target = self.path(name)
        fx.write_panic(target, header, body)
        return target


class ParseTest(FixtureTest):
    def test_trailing_system_profile_text_is_ignored(self):
        target = self.path("trailer.panic")
        fx.write_panic(target, trailer="\n\nSystem Profile:\nBoot Volume File System Type: apfs\n")
        result = report.analyze(target)
        self.assertEqual(result["class"], "launchd-exit")
        self.assertEqual(result["suspects"][0]["procname"], "pagefind_extended")

    def test_kernel_task_is_never_a_suspect(self):
        result = report.analyze(self.write("k.panic"))
        self.assertNotIn(0, [s["pid"] for s in result["suspects"]])
        self.assertEqual(result["suspects"][0]["stuck"], 512)

    def test_parse_launchd_sigbus(self):
        path = self.write("a.panic")
        parsed = report.parse_report(path)
        self.assertEqual(parsed["header"]["bug_type"], "210")
        self.assertIn("processByPid", parsed["body"])

    def test_header_and_signal(self):
        header = fx.build_header(os_version="Darwin 23.0.0",
                                 timestamp="2026-01-01 00:00:00")
        path = self.write("b.panic", header=header)
        result = report.analyze(path)
        self.assertEqual(result["os_version"], "Darwin 23.0.0")
        self.assertEqual(result["timestamp"], "2026-01-01 00:00:00")


class ClassifyTest(FixtureTest):
    def test_sigbus(self):
        result = report.classify("initproc exited -- exit reason namespace 2 subcode 0xa")
        self.assertEqual(result["class"], "launchd-exit")
        self.assertEqual(result["signal"], "SIGBUS")

    def test_signal_map(self):
        for subcode, name in (("0xb", "SIGSEGV"), ("0x9", "SIGKILL"), ("0x6", "SIGABRT")):
            result = report.classify(
                "initproc exited -- exit reason namespace 2 subcode %s" % subcode)
            self.assertEqual(result["signal"], name)

    def test_other_namespace(self):
        result = report.classify(
            "initproc exited -- exit reason namespace 3 subcode 0x2")
        self.assertEqual(result["class"], "launchd-exit")
        self.assertIsNone(result["signal"])
        self.assertIn("namespace 3", result["label"])

    def test_watchdog(self):
        result = report.classify(
            "watchdog timeout: no checkins from watchdogd in 92 seconds")
        self.assertEqual(result["class"], "watchdog-timeout")

    def test_watchdog_requires_watchdogd(self):
        result = report.classify("watchdog timeout for some other reason")
        self.assertEqual(result["class"], "other")

    def test_other_excerpt_redacts_paths(self):
        text = ("panic(cpu 1 caller 0x1): Kernel trap at /Users/alice/secret/project/file.c:42 "
                "while mapping /private/var/folders/xy/abc and @/AppleInternal/Library/x.c")
        result = report.classify(text)
        self.assertNotIn("alice", result["excerpt"])
        self.assertNotIn("/private", result["excerpt"])
        self.assertNotIn("AppleInternal", result["excerpt"])
        self.assertIn("<path>:42", result["excerpt"])

    def test_other_excerpt(self):
        text = "x" * 200
        result = report.classify(text)
        self.assertEqual(result["class"], "other")
        self.assertEqual(result["excerpt"], text[:160])
        self.assertEqual(len(result["excerpt"]), 160)


class RankTest(unittest.TestCase):
    def test_dominant_process(self):
        suspects, system_wide = report.rank_suspects(fx.launchd_sigbus_body())
        self.assertEqual(system_wide, 515)
        self.assertEqual(suspects[0]["pid"], 1234)
        self.assertEqual(suspects[0]["procname"], "pagefind_extended")
        self.assertEqual(suspects[0]["stuck"], 512)
        self.assertEqual(suspects[0]["threads"], 515)
        self.assertEqual(suspects[0]["top_wait_count"], 511)
        self.assertEqual(suspects[1]["pid"], 99)

    def test_sort_desc(self):
        suspects, _ = report.rank_suspects(fx.watchdog_body())
        self.assertEqual(suspects[0]["pid"], 88)
        self.assertEqual(suspects[0]["stuck"], 2)


class AnalyzeTest(FixtureTest):
    def test_launchd_sigbus_analysis(self):
        path = self.write("s.panic", body=fx.launchd_sigbus_body())
        result = report.analyze(path)
        self.assertEqual(result["class"], "launchd-exit")
        self.assertEqual(result["signal"], "SIGBUS")
        self.assertFalse(result["memory_pressure"])
        self.assertEqual(result["system_uninterruptible"], 515)
        text = report.render_text(result)
        self.assertIn("512 of 515 threads uninterruptible", text)
        self.assertIn("511 on one wait event", text)
        self.assertIn("kern.num_files", text)

    def test_watchdog_analysis(self):
        path = self.write("w.panic", body=fx.watchdog_body())
        result = report.analyze(path)
        self.assertEqual(result["class"], "watchdog-timeout")
        self.assertTrue(result["memory_pressure"])
        self.assertIn("kern.num_vnodes", report.render_text(result))

    def test_missing_processbypid(self):
        path = self.write("m.panic", body=fx.minimal_body())
        result = report.analyze(path)
        self.assertEqual(result["suspects"], [])
        self.assertEqual(result["system_uninterruptible"], 0)
        self.assertIn("top suspect: none", report.render_verdict(result))

    def test_odd_fields_do_not_crash(self):
        body = fx.other_body(panic_string="initproc exited -- exit reason namespace 2 subcode 0xa")
        body["processByPid"] = {
            "abc": "junk",
            "77": {"procname": "b", "threadById": {"1": "junk", "2": None}},
            "78": {"threadById": {"9": {"state": "TH_UNINT",
                                        "waitEvent": ["x"]}}},
            "9": None,
        }
        path = self.write("o.panic", body=body)
        result = report.analyze(path)
        self.assertEqual(result["class"], "launchd-exit")
        self.assertEqual(result["system_uninterruptible"], 0)


class BadFileTest(FixtureTest):
    def test_not_json(self):
        path = self.path("plain.txt")
        fx.write_text(path)
        with self.assertRaises(report.NotPanicReport):
            report.parse_report(path)

    def test_empty_file(self):
        path = self.path("empty.panic")
        open(path, "w").close()
        with self.assertRaises(report.NotPanicReport):
            report.parse_report(path)

    def test_missing_file(self):
        with self.assertRaises(report.NotPanicReport):
            report.parse_report(self.path("nope.panic"))

    def test_header_without_body(self):
        path = self.path("h.panic")
        fx.write_text(path, '{"bug_type": "210"}')
        with self.assertRaises(report.NotPanicReport):
            report.parse_report(path)