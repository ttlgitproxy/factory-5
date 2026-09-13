import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "observe_signing_input_provenance.py"
SPEC = importlib.util.spec_from_file_location("signing_input_provenance", SCRIPT)
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class SigningInputProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-provenance-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.p12_path = self.directory / "synthetic private p12.p12"
        self.profile_path = self.directory / "synthetic private profile.mobileprovision"
        self.p12_bytes = b"synthetic-only-p12-CERT-IDENTIFIER\x00\xff\r\n"
        self.profile_bytes = b"synthetic-only-profile-CERT-IDENTIFIER\x00\x80\n"
        self.p12_path.write_bytes(self.p12_bytes)
        self.profile_path.write_bytes(self.profile_bytes)
        self.environment = {
            "CERTIFICATE_PATH": str(self.p12_path),
            "PROFILE_PATH": str(self.profile_path),
            "DIAGNOSTIC_EXPECTED_P12_SHA256": hashlib.sha256(self.p12_bytes).hexdigest(),
            "DIAGNOSTIC_EXPECTED_PROFILE_SHA256": hashlib.sha256(
                self.profile_bytes
            ).hexdigest(),
        }

    def run_observer(self, environment=None):
        # Remove inherited diagnostic inputs; fixtures never use real signing data.
        child_environment = {
            key: value
            for key, value in os.environ.items()
            if key not in self.environment
        }
        child_environment.update(self.environment if environment is None else environment)
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=child_environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_no_leaks(self, stdout, stderr):
        output = stdout + stderr
        for value in self.environment.values():
            self.assertNotIn(value, output)
        for value in (self.p12_bytes, self.profile_bytes):
            self.assertNotIn(hashlib.sha256(value).hexdigest(), output)
            self.assertNotIn(base64.b64encode(value).decode("ascii"), output)
        self.assertNotIn("CERT-IDENTIFIER", output)
        self.assertNotIn("synthetic-only", output)
        self.assertNotIn("Traceback", output)
        self.assertNotIn("SECRET-SENTINEL", output)
        self.assertNotRegex(output, r"[0-9a-fA-F]{64}")

    def assert_comparison(self, result, p12, profile):
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout,
            "INPUT_PROVENANCE_STATUS=compared\n"
            f"P12_FILE_MATCH={p12}\n"
            f"PROFILE_FILE_MATCH={profile}\n",
        )
        self.assertEqual(result.stderr, "")
        self.assert_no_leaks(result.stdout, result.stderr)

    def assert_error(self, result, category):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr, f"::error::INPUT_PROVENANCE_ERROR={category}\n"
        )
        self.assert_no_leaks(result.stdout, result.stderr)

    def test_all_match_combinations_succeed_without_changing_files(self):
        for p12_match, profile_match in ((True, True), (False, True),
                                         (True, False), (False, False)):
            with self.subTest(p12=p12_match, profile=profile_match):
                environment = self.environment.copy()
                if not p12_match:
                    environment["DIAGNOSTIC_EXPECTED_P12_SHA256"] = "0" * 64
                if not profile_match:
                    environment["DIAGNOSTIC_EXPECTED_PROFILE_SHA256"] = "0" * 64
                self.assert_comparison(
                    self.run_observer(environment),
                    "yes" if p12_match else "no",
                    "yes" if profile_match else "no",
                )
                self.assertEqual(self.p12_path.read_bytes(), self.p12_bytes)
                self.assertEqual(self.profile_path.read_bytes(), self.profile_bytes)

    def test_uppercase_and_surrounding_whitespace_are_normalized(self):
        environment = self.environment.copy()
        for variable in ("DIAGNOSTIC_EXPECTED_P12_SHA256",
                         "DIAGNOSTIC_EXPECTED_PROFILE_SHA256"):
            environment[variable] = " \t\r\n" + environment[variable].upper() + "\n\t "
        self.assert_comparison(self.run_observer(environment), "yes", "yes")

    def test_missing_expected_hashes(self):
        for label in ("p12", "profile"):
            variable = f"DIAGNOSTIC_EXPECTED_{label.upper()}_SHA256"
            for value in (None, "", " \t\r\n"):
                with self.subTest(label=label, value=value):
                    environment = self.environment.copy()
                    if value is None:
                        del environment[variable]
                    else:
                        environment[variable] = value
                    self.assert_error(
                        self.run_observer(environment), f"expected_{label}_missing"
                    )

    def test_invalid_expected_hashes(self):
        invalid_values = (
            "a" * 63,
            "a" * 65,
            "g" * 64,
            "a" * 31 + " " + "b" * 32,
            "a" * 32 + "\n" + "b" * 32,
            "0x" + "a" * 64,
            "\uff41" * 64,
            "SECRET-SENTINEL\n::error::injected",
        )
        for label in ("p12", "profile"):
            variable = f"DIAGNOSTIC_EXPECTED_{label.upper()}_SHA256"
            for value in invalid_values:
                with self.subTest(label=label, value=value):
                    environment = self.environment.copy()
                    environment[variable] = value
                    self.assert_error(
                        self.run_observer(environment), f"expected_{label}_invalid"
                    )

    def test_missing_input_paths(self):
        for variable, label in (("CERTIFICATE_PATH", "p12"), ("PROFILE_PATH", "profile")):
            for value in (None, ""):
                with self.subTest(label=label, value=value):
                    environment = self.environment.copy()
                    if value is None:
                        del environment[variable]
                    else:
                        environment[variable] = value
                    self.assert_error(
                        self.run_observer(environment), f"{label}_path_missing"
                    )

    def test_missing_files_and_unreadable_directory_inputs(self):
        for variable, label in (("CERTIFICATE_PATH", "p12"), ("PROFILE_PATH", "profile")):
            for path, category in (
                (self.directory / "SECRET-SENTINEL-missing", "file_missing"),
                (self.directory, "file_unreadable"),
            ):
                with self.subTest(label=label, category=category):
                    environment = self.environment.copy()
                    environment[variable] = str(path)
                    self.assert_error(
                        self.run_observer(environment), f"{label}_{category}"
                    )

    def test_permission_and_read_errors_do_not_leak_os_messages(self):
        original_read_bytes = Path.read_bytes
        for path, label in ((self.p12_path, "p12"), (self.profile_path, "profile")):
            for exception in (
                PermissionError(13, "SECRET-SENTINEL denied", str(path)),
                OSError(5, "SECRET-SENTINEL read failure", str(path)),
            ):
                with self.subTest(label=label, error=type(exception).__name__):
                    def read_bytes(candidate):
                        if candidate == path:
                            raise exception
                        return original_read_bytes(candidate)

                    stdout, stderr = io.StringIO(), io.StringIO()
                    # Simulate OS failures at the I/O boundary, not observer logic.
                    with patch.dict(os.environ, self.environment, clear=True), \
                            patch.object(Path, "read_bytes", read_bytes), \
                            redirect_stdout(stdout), redirect_stderr(stderr):
                        result = OBSERVER.main()
                    self.assert_error(
                        subprocess.CompletedProcess(
                            [], result, stdout.getvalue(), stderr.getvalue()
                        ),
                        f"{label}_file_unreadable",
                    )

    def test_invalid_path_does_not_leak_value(self):
        for variable, label in (("CERTIFICATE_PATH", "p12"), ("PROFILE_PATH", "profile")):
            with self.subTest(label=label):
                environment = self.environment.copy()
                # NUL cannot be passed in a child process environment.
                environment[variable] = "SECRET-SENTINEL\x00invalid"
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(OBSERVER.os, "environ", environment), \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    result = OBSERVER.main()
                self.assert_error(
                    subprocess.CompletedProcess(
                        [], result, stdout.getvalue(), stderr.getvalue()
                    ),
                    f"{label}_path_invalid",
                )

    def test_complete_binary_file_bytes_are_hashed(self):
        for variable, path in (("DIAGNOSTIC_EXPECTED_P12_SHA256", self.p12_path),
                               ("DIAGNOSTIC_EXPECTED_PROFILE_SHA256", self.profile_path)):
            with self.subTest(variable=variable):
                data = bytes(range(256)) * 8192 + b"synthetic-last-byte"
                path.write_bytes(data)
                self.environment[variable] = hashlib.sha256(data).hexdigest()
                self.assert_comparison(self.run_observer(), "yes", "yes")
                path.write_bytes(data[:-1] + b"!")
                self.assert_comparison(
                    self.run_observer(),
                    "no" if path == self.p12_path else "yes",
                    "no" if path == self.profile_path else "yes",
                )
                path.write_bytes(data)

    def test_empty_file_is_a_byte_observation_not_a_credential_validation(self):
        self.p12_path.write_bytes(b"")
        self.assert_comparison(self.run_observer(), "no", "yes")
        self.environment["DIAGNOSTIC_EXPECTED_P12_SHA256"] = hashlib.sha256(b"").hexdigest()
        self.assert_comparison(self.run_observer(), "yes", "yes")


class WorkflowWiringTests(unittest.TestCase):
    def test_private_build_outputs_are_not_published(self):
        workflows = ROOT / ".github" / "workflows"
        build = (workflows / "build-and-test.yml").read_text(encoding="utf-8")
        deploy = (workflows / "deploy-testflight.yml").read_text(encoding="utf-8")
        for workflow in (build, deploy):
            self.assertNotIn("uses: actions/cache@", workflow)
            self.assertNotIn("uses: actions/upload-artifact@", workflow)
            self.assertNotIn(".squad/", workflow)
            for variable, exported in (
                ("fallback_project_id", "PROJECT_ID"),
                ("fallback_sha", "SHA"),
            ):
                self.assertLess(
                    workflow.index(f'echo "::add-mask::${variable}"'),
                    workflow.index(f'echo "{exported}=${variable}"'),
                )
        self.assertNotIn("invalid HTTP code '${http_code}'", deploy)
        self.assertNotIn("deploy.log artifact", deploy)
        self.assertIn(
            'danger-swift local --base "origin/${DANGER_BASE_REF}" '
            '>/dev/null 2>&1 || DANGER_RESULT=$?',
            build,
        )
        self.assertLess(
            deploy.index('echo "::add-mask::$masked_detail"'),
            deploy.index('echo "DEPLOY_ERROR_DETAIL<<${eof_guard}"'),
        )
        self.assertLess(
            deploy.index('echo "::add-mask::$masked_error"'),
            deploy.index('echo "DEPLOY_ERROR<<__DEPLOY_ERROR_EOF__"'),
        )
        for variable in ("masked_detail", "masked_error"):
            self.assertIn(
                f'{variable}="${{{variable}//$\'\\r\'/\'%0D\'}}"', deploy
            )
            self.assertIn(
                f'{variable}="${{{variable}//$\'\\n\'/\'%0A\'}}"', deploy
            )

    def test_observer_order_secrets_and_sparse_checkout(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-testflight.yml").read_text(
            encoding="utf-8"
        )
        steps = workflow.split("      - name: ")[1:]
        names = [step.splitlines()[0] for step in steps]
        index = names.index("Import provisioning profile")
        self.assertEqual(
            names[index:index + 3],
            [
                "Import provisioning profile",
                "Observe signing input file provenance (temporary)",
                "Validate signing identity against provisioning profile",
            ],
        )
        self.assertEqual(
            steps[index + 1],
            "Observe signing input file provenance (temporary)\n"
            "        env:\n"
            "          DIAGNOSTIC_EXPECTED_P12_SHA256: "
            "${{ secrets.DIAGNOSTIC_EXPECTED_P12_SHA256 }}\n"
            "          DIAGNOSTIC_EXPECTED_PROFILE_SHA256: "
            "${{ secrets.DIAGNOSTIC_EXPECTED_PROFILE_SHA256 }}\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          /usr/bin/python3 .github/scripts/observe_signing_input_provenance.py\n\n",
        )
        checkout = steps[names.index("Checkout CI configuration")]
        self.assertIn(
            "          sparse-checkout: |\n"
            "            .github/sanitize-patterns.json\n"
            "            .github/scripts/observe_signing_input_provenance.py\n"
            "          sparse-checkout-cone-mode: false\n",
            checkout,
        )
        self.assertTrue(SCRIPT.is_file())


if __name__ == "__main__":
    unittest.main()
