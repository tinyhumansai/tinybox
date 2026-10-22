"""Check that feature CI supplies the tools its host fixtures require."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class FeatureEnvironmentTests(unittest.TestCase):
    def test_macos_exposes_util_linux_before_running_both_test_suites(self):
        """The keg-only setsid must be on PATH for every Cargo test invocation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            prefix = root / "util-linux"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin/setsid").write_text("#!/bin/sh\nexit 0\n")
            (prefix / "bin/setsid").chmod(0o755)
            fixtures = {
                "brew": '#!/bin/sh\ncase "$1" in\ninstall) exit 0 ;;\n--prefix) printf "%s\\n" "$FIXTURE_PREFIX" ;;\n*) exit 1 ;;\nesac\n',
                "python3": "#!/bin/sh\nexit 0\n",
                "cargo": '#!/bin/sh\n[ "$(command -v setsid)" = "$FIXTURE_PREFIX/bin/setsid" ] || exit 1\nprintf "%s\\n" "$*" >> "$FIXTURE_CALLS"\n',
            }
            for name, source in fixtures.items():
                path = tools / name
                path.write_text(source)
                path.chmod(0o755)
            calls = root / "calls"
            env = dict(os.environ, RUNNER_OS="macOS", FIXTURE_PREFIX=str(prefix),
                       FIXTURE_CALLS=str(calls), PATH=str(tools) + os.pathsep + "/usr/bin:/bin")
            result = subprocess.run(["bash", str(ROOT / "scripts/test-features.sh")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), [
                "test --locked --workspace", "test --locked --workspace --all-features"])

class WindowsFeatureEnvironmentTests(unittest.TestCase):
    def test_windows_supplies_native_shell_before_running_both_test_suites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            calls = root / "calls"
            ready = root / "ready"
            fixtures = {
                "cygpath": "#!/bin/sh\n[ \"$*\" = \"-w /usr/bin\" ] || exit 1\nprintf \"%s\\n\" \"$FIXTURE_BIN\"\n",
                "pwsh": "#!/bin/sh\n[ \"$*\" = \"-NoProfile -File scripts/test-windows-fixtures.ps1\" ] && exit 0\n[ \"$*\" = \"-NoProfile -File scripts/prepare-windows-fixtures.ps1 -PosixBin $FIXTURE_BIN\" ] || exit 1\ntouch \"$FIXTURE_READY\"\n",
                "python3": "#!/bin/sh\nexit 0\n",
                "cargo": (
                    "#!/bin/sh\n[ -f \"$FIXTURE_READY\" ] || exit 1\n"
                    "printf \"%s\\n\" \"$*\" >> \"$FIXTURE_CALLS\"\n"
                    "case \"$1\" in\n"
                    "metadata) printf '%s\\n' '{\"workspace_members\":[\"fixture 0.1.0 (path+file:///fixture)\"],\"packages\":[{\"id\":\"fixture 0.1.0 (path+file:///fixture)\",\"name\":\"tinybox-fixture\",\"targets\":[{\"kind\":[\"lib\"]}]}]}' ;;\n"
                    "tree) printf '%s\\n' 'tinybox-fixture v0.1.0' ;;\n"
                    "esac\n"
                ),
            }
            for name, source in fixtures.items():
                path = tools / name
                path.write_text(source)
                path.chmod(0o755)
            env = dict(os.environ, RUNNER_OS="Windows", FIXTURE_BIN="C:/Git/usr/bin",
                       FIXTURE_READY=str(ready), FIXTURE_CALLS=str(calls),
                       PATH=str(tools) + os.pathsep + "/usr/bin:/bin")
            result = subprocess.run(["bash", str(ROOT / "scripts/test-features.sh")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), [
                "test --locked --workspace",
                "test --locked --workspace --all-features",
                "metadata --locked --format-version 1 --no-deps",
                "tree --locked --format {p} --prefix none -e normal,build -p tinybox-fixture",
                "tree --locked --format {p} --prefix none -e normal,build -p tinybox-fixture --no-default-features",
                "tree --locked --format {p} --prefix none -e normal,build -p tinybox-fixture --all-features",
            ])

if __name__ == "__main__":
    unittest.main()
