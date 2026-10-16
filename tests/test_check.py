import os
import platform
import sys
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from panicsight import check as ck  # noqa: E402

LOW = {
    "kern.num_files": 5000,
    "kern.maxfiles": 20000,
    "kern.maxfilesperproc": 10240,
    "kern.num_vnodes": 9000,
    "kern.maxvnodes": 20000,
    "kern.free_vnodes": 4000,
}


class EvaluateTest(unittest.TestCase):
    def test_below_thresholds(self):
        result = ck.evaluate(LOW)
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["status"], "OK")
        self.assertAlmostEqual(result["file_table_pct"], 25.0)
        self.assertAlmostEqual(result["free_vnode_pct"], 20.0)

    def test_file_table_at_threshold_warns(self):
        values = dict(LOW, **{"kern.num_files": 10000})
        result = ck.evaluate(values)
        self.assertEqual(result["status"], "WARN")
        self.assertIn("kern.maxfiles", result["warnings"][0])

    def test_file_table_below_threshold_no_warn(self):
        values = dict(LOW, **{"kern.num_files": 9999})
        result = ck.evaluate(values)
        self.assertEqual(result["warnings"], [])

    def test_free_vnodes_below_threshold_warns(self):
        values = dict(LOW, **{"kern.free_vnodes": 1000})
        result = ck.evaluate(values)
        self.assertEqual(result["status"], "WARN")
        self.assertIn("kern.maxvnodes", result["warnings"][0])

    def test_free_vnodes_at_threshold_no_warn(self):
        values = dict(LOW, **{"kern.free_vnodes": 2000})
        result = ck.evaluate(values)
        self.assertEqual(result["warnings"], [])

    def test_both_thresholds_warn(self):
        values = dict(LOW, **{"kern.num_files": 15000, "kern.free_vnodes": 500})
        result = ck.evaluate(values)
        self.assertEqual(len(result["warnings"]), 2)

    def test_missing_values_no_crash(self):
        result = ck.evaluate({})
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["status"], "OK")
        self.assertIsNone(result["file_table_pct"])


class CollectTest(unittest.TestCase):
    def test_injected_runner(self):
        runner = lambda name: {"kern.maxfiles": 7}.get(name)
        result = ck.collect_values(runner)
        self.assertEqual(result["kern.maxfiles"], 7)
        self.assertEqual(len(result), len(ck.SYSCTL_NAMES))
        self.assertIsNone(result["kern.num_files"])


@unittest.skipIf(platform.system() != "Darwin", "sysctl probe requires macOS")
class RunCheckTest(unittest.TestCase):
    def test_exit_zero_on_macos(self):
        code, text, evaluation = ck.run_check()
        self.assertEqual(code, 0)
        self.assertIn("status:", text)
        self.assertIn(evaluation["status"], ("OK", "WARN"))


class NonMacTest(unittest.TestCase):
    def test_non_macos_returns_message_and_skips_sysctl(self):
        calls = []
        original = ck.platform.system
        ck.platform.system = lambda: "Linux"
        try:
            code, message, evaluation = ck.run_check(lambda name: calls.append(name))
        finally:
            ck.platform.system = original
        self.assertEqual(code, 2)
        self.assertIn("requires macOS", message)
        self.assertIsNone(evaluation)
        self.assertEqual(calls, [])


class RenderTest(unittest.TestCase):
    def test_text_marks_warning(self):
        result = ck.evaluate(dict(LOW, **{"kern.num_files": 13000,
                                          "kern.free_vnodes": 100}))
        text = ck.render_text(result)
        self.assertEqual(result["status"], "WARN")
        self.assertIn("file table use: 65.0% of kern.maxfiles [WARNING]", text)
        self.assertIn("free vnodes: 0.5% of kern.maxvnodes [WARNING]", text)
        self.assertIn("status: WARN", text)


if __name__ == "__main__":
    unittest.main()