"""hooks/run.sh: the shell launcher that finds a working Python for the plugin hooks.

Each test builds its own PATH out of small stand-in commands, so the cases a Windows machine shows
(`python3` is a dead Microsoft Store shortcut, the real interpreter is `python` or `py -3`) run on POSIX."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "hooks", "run.sh")
SH = shutil.which("sh")
STORE_HINT = "Python was not found; run without arguments to install from the Microsoft Store"
PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}}


@unittest.skipUnless(SH and os.name != "nt", "needs a POSIX sh and executable stand-in scripts")
class Launcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dirs = []

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, folder, name, body):
        d = os.path.join(self.tmp.name, folder)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n" + body + "\n")
        os.chmod(path, 0o755)
        if d not in self.dirs:
            self.dirs.append(d)

    def real(self, folder, name):
        self.command(folder, name, 'exec "%s" "$@"' % sys.executable)

    def dead(self, folder, name, code=49):
        self.command(folder, name, 'echo "%s" >&2\nexit %d' % (STORE_HINT, code))

    def run_hook(self, script=RUN):
        env = {"PATH": os.pathsep.join(self.dirs), "RAYNSIS_INSPECTOR_HOME": os.path.join(self.tmp.name, "home")}
        payload = dict(PAYLOAD, cwd=self.tmp.name)
        return subprocess.run([SH, script, "hook"], input=json.dumps(payload).encode(), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

    def assert_denied(self, p):
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout.decode())  # exactly one JSON object: a stand-in's own output must not leak in
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("tool.no-secret-files", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_a_real_python3_is_used_directly(self):
        self.real("bin", "python3")
        self.dead("bin", "python")  # never reached
        self.assert_denied(self.run_hook())

    def test_dead_store_shortcut_falls_back_to_python(self):
        self.dead("WindowsApps", "python3")
        self.real("Python312", "python")
        p = self.run_hook()
        self.assert_denied(p)
        self.assertNotIn(b"Microsoft Store", p.stderr)

    def test_dead_python3_and_python_fall_back_to_the_py_launcher(self):
        self.dead("WindowsApps", "python3")
        self.dead("WindowsApps", "python")
        self.command("Windows", "py", '[ "$1" = "-3" ] || exit 64\nshift\nexec "%s" "$@"' % sys.executable)
        self.assert_denied(self.run_hook())

    def test_store_python_that_works_is_used(self):
        self.real("WindowsApps", "python3")
        self.assert_denied(self.run_hook())

    def test_a_python_older_than_3_9_is_skipped(self):
        self.dead("WindowsApps", "python3")
        self.command("old", "python", "exit 1")  # what the version probe returns on an old interpreter
        self.command("Windows", "py", 'shift\nexec "%s" "$@"' % sys.executable)
        self.assert_denied(self.run_hook())

    def test_no_python_at_all_says_so_and_prints_no_decision(self):
        self.dead("WindowsApps", "python3")
        self.dead("WindowsApps", "python")
        p = self.run_hook()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, b"")
        self.assertIn(b"no working Python 3.9+", p.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_plugin_path_with_a_space(self):
        spaced = os.path.join(self.tmp.name, "Program Files", "plugin")
        os.makedirs(os.path.dirname(spaced))
        os.symlink(ROOT, spaced)
        self.real("bin", "python3")
        self.assert_denied(self.run_hook(os.path.join(spaced, "hooks", "run.sh")))


class LauncherFile(unittest.TestCase):
    def test_launcher_has_unix_line_endings_and_git_keeps_them(self):
        with open(RUN, "rb") as f:
            self.assertNotIn(b"\r", f.read())
        with open(os.path.join(ROOT, ".gitattributes"), encoding="utf-8") as f:
            self.assertIn("*.sh text eol=lf", f.read())

    def test_launcher_uses_no_external_command(self):
        # the usual case must cost one shell and nothing else: no dirname, grep, sed or head
        with open(RUN, encoding="utf-8") as f:
            code = [line for line in f if not line.lstrip().startswith("#")]
        for word in ("dirname", "basename", "grep", "sed", "awk", "head", "uname", "which"):
            self.assertFalse(any(word in line for line in code), word)


if __name__ == "__main__":
    unittest.main()
