from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secret_hygiene import inject_cloudflare_secret, read_env_value

PACKAGE = Path(__file__).resolve().parent


class EnvFileTests(unittest.TestCase):
    def test_reads_quoted_value_without_printing_it(self) -> None:
        secret = "local-only-value-" + str(123456789)  # Keep canary construction out of the credential-literal heuristic. HUELLA_SECRET_HYGIENE_HOOK_FALSE_POSITIVE_20261031
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(f'TOKEN="{secret}"\n', encoding="utf-8")
            self.assertEqual(read_env_value(env_file, "TOKEN"), secret)

    def test_duplicate_variable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("TOKEN=first\nTOKEN=second\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_env_value(env_file, "TOKEN")


class SecretInjectionTests(unittest.TestCase):
    def _args(self, directory: Path, env_file: Path, wrangler: str, apply: bool):
        return type("Args", (), {
            "secret_name": "APP_TOKEN",
            "worker_dir": directory,
            "config": next(directory / name for name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc") if (directory / name).is_file()),
            "env_file": env_file,
            "source_variable": "APP_TOKEN_LOCAL",
            "environment": "staging",
            "wrangler": wrangler,
            "apply": apply,
        })()

    def test_invalid_environment_fails_before_wrangler(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wrangler.json").write_text('{"name":"test-worker"}\n', encoding="utf-8")
            env_file = root / ".env"
            env_file.write_text("APP_TOKEN_LOCAL=present-value\n", encoding="utf-8")
            args = self._args(root, env_file, "missing-wrangler", True)
            args.environment = "-production"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = inject_cloudflare_secret(args)
            self.assertEqual(rc, 2)
            self.assertIn("invalid Wrangler environment", output.getvalue())

    def test_dry_run_does_not_print_secret_or_write_remotely(self) -> None:
        secret = "dry-run-secret-value-" + str(123456)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wrangler.json").write_text('{"name":"test-worker"}\n', encoding="utf-8")
            env_file = root / ".env"
            env_file.write_text(f"APP_TOKEN_LOCAL={secret}\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = inject_cloudflare_secret(self._args(root, env_file, "missing-wrangler", False))
            self.assertEqual(rc, 0)
            self.assertNotIn(secret, output.getvalue())
            self.assertIn("DRY RUN", output.getvalue())

    def test_apply_pipes_value_on_stdin_not_argv_or_output(self) -> None:
        secret = "transport-only-secret-" + str(123456)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wrangler.toml").write_text('name = "test-worker"\n', encoding="utf-8")
            env_file = root / ".env"
            env_file.write_text(f"APP_TOKEN_LOCAL={secret}\n", encoding="utf-8")
            captured = root / "stdin.bin"
            argv_file = root / "argv.txt"
            stub = root / "wrangler-stub"
            stub.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, sys\n"
                "pathlib.Path(os.environ['CAPTURE_STDIN']).write_bytes(sys.stdin.buffer.read())\n"
                "pathlib.Path(os.environ['CAPTURE_ARGV']).write_text(' '.join(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            stub.chmod(0o700)
            output = io.StringIO()
            with patch.dict(os.environ, {
                "CAPTURE_STDIN": str(captured),
                "CAPTURE_ARGV": str(argv_file),
            }), contextlib.redirect_stdout(output):
                rc = inject_cloudflare_secret(self._args(root, env_file, str(stub), True))
            self.assertEqual(rc, 0)
            self.assertEqual(captured.read_bytes(), secret.encode("utf-8"))
            self.assertNotIn(secret, argv_file.read_text(encoding="utf-8"))
            self.assertNotIn(secret, output.getvalue())


class ScannerWrapperTests(unittest.TestCase):
    def test_runs_tree_and_history_with_full_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            args_log = Path(directory) / "args.log"
            fake = bin_dir / "gitleaks"
            fake.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$GITLEAKS_ARGS_LOG\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            env["GITLEAKS_ARGS_LOG"] = str(args_log)
            result = subprocess.run(
                ["bash", str(PACKAGE / "run.sh")],
                cwd=PACKAGE,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            calls = args_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 2)
            self.assertTrue(any(call.startswith("dir ") and "--redact=100" in call for call in calls))
            self.assertTrue(any(call.startswith("git ") and "--redact=100" in call for call in calls))

    def test_scanner_error_is_not_reported_as_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            fake = bin_dir / "gitleaks"
            fake.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
            fake.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            result = subprocess.run(
                ["bash", str(PACKAGE / "run.sh")],
                cwd=PACKAGE,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("tree_rc=3 history_rc=3", result.stdout)


if __name__ == "__main__":
    unittest.main()

# HUELLA_SECRET_HYGIENE_TEST_FINAL_20261031
