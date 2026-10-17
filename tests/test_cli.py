import contextlib
import io
import json
import os
import platform
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from panicsight import __version__, cli  # noqa: E402

import make_fixtures as fx  # noqa: E402


class CliBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def fixture(self, name, header=None, body=None):
        path = os.path.join(self.dir, name)
        fx.write_panic(path, header, body)
        return path

    def run_main(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()


class VersionCliTest(CliBase):
    def test_version_without_subcommand(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exc:
                cli.main(["--version"])
        self.assertEqual(exc.exception.code, 0)
        self.assertEqual(stdout.getvalue(), "panicsight %s\n" % __version__)
        self.assertEqual(__version__, "0.2.0")
        self.assertEqual(stderr.getvalue(), "")


class AnalyzeCliTest(CliBase):
    def test_json_mode(self):
        path = self.fixture("a.panic", body=fx.launchd_sigbus_body())
        code, out, err = self.run_main(["analyze", path, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        for key in ("class", "signal", "memory_pressure", "system_uninterruptible",
                    "suspects", "os_version", "timestamp"):
            self.assertIn(key, payload)
        self.assertEqual(payload["class"], "launchd-exit")
        self.assertEqual(payload["signal"], "SIGBUS")
        self.assertFalse(payload["memory_pressure"])
        self.assertEqual(payload["system_uninterruptible"], 515)
        self.assertEqual(payload["suspects"][0]["procname"], "pagefind_extended")

    def test_text_mode(self):
        path = self.fixture("w.panic", body=fx.watchdog_body())
        code, out, err = self.run_main(["analyze", path])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("watchdog-timeout"))
        self.assertIn("outside the kernel: 2.", out)
        self.assertIn("kern.num_vnodes", out)

    def test_not_panic_report_exits_two(self):
        path = os.path.join(self.dir, "plain.txt")
        fx.write_text(path)
        code, out, err = self.run_main(["analyze", path])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("error:"))
        self.assertEqual(len(err.strip().splitlines()), 1)

    def test_missing_file_exits_two(self):
        code, out, err = self.run_main(["analyze", os.path.join(self.dir, "gone.panic")])
        self.assertEqual(code, 2)


@unittest.skipIf(platform.system() != "Darwin", "check requires macOS sysctl")
class CheckCliTest(CliBase):
    def test_check_text(self):
        code, out, err = self.run_main(["check"])
        self.assertEqual(code, 0)
        self.assertIn("status:", out)

    def test_check_json(self):
        code, out, err = self.run_main(["check", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("status", payload)
        self.assertIn("warnings", payload)


if __name__ == "__main__":
    unittest.main()
