import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from swbom import generate, main, parse_package_lock

class SbomTests(unittest.TestCase):
    def test_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"requirements.txt"; path.write_text("foo==1.0\n# comment\nbar>=2\n",encoding="utf-8")
            bom=generate(path); self.assertEqual([c["name"] for c in bom["components"]],["bar","foo"])

    def test_requirements_with_extras_and_environment_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_text(
                "requests[socks,security]>=2.31; python_version < '3.13'\n",
                encoding="utf-8",
            )
            bom = generate(path)
            self.assertEqual(
                bom["components"],
                [{"name": "requests", "version": "2.31", "type": "python"}],
            )

    def test_requirements_strips_inline_comments_from_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_text("cryptography==42.0.5  # CVE fix\n", encoding="utf-8")
            bom = generate(path)
            self.assertEqual(
                bom["components"],
                [{"name": "cryptography", "version": "42.0.5", "type": "python"}],
            )

    def test_requirements_compound_version_constraint_is_not_reported_as_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_text("urllib3>=1.26,<3\n", encoding="utf-8")
            bom = generate(path)
            self.assertEqual(
                bom["components"],
                [{"name": "urllib3", "version": "UNKNOWN", "type": "python"}],
            )

    def test_requirements_include_direct_url_and_editable_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_text(
                "my-driver[diagnostics] @ https://packages.example.invalid/my-driver.tar.gz\n"
                "-e git+https://git.example.invalid/tools.git@main#egg=diag-tools\n",
                encoding="utf-8",
            )
            bom = generate(path)
            self.assertEqual(
                bom["components"],
                [
                    {"name": "diag-tools", "version": "UNKNOWN", "type": "python"},
                    {"name": "my-driver", "version": "UNKNOWN", "type": "python"},
                ],
            )

    def test_package_lock_v1_includes_nested_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"package-lock.json"
            path.write_text(
                '{"lockfileVersion":1,"dependencies":{'
                '"app":{"version":"1.0.0","dependencies":{'
                '"nested-lib":{"version":"2.0.0"}}}}}',
                encoding="utf-8",
            )
            bom=generate(path)
            self.assertEqual(
                [(component["name"], component["version"]) for component in bom["components"]],
                [("app", "1.0.0"), ("nested-lib", "2.0.0")],
            )

    def test_package_lock_v3_derives_names_from_node_modules_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "package-lock.json"
            path.write_text(
                '{"lockfileVersion":3,"packages":{'
                '"":{"name":"app","version":"1.0.0"},'
                '"node_modules/left-pad":{"version":"1.3.0"},'
                '"node_modules/@scope/tool":{"version":"2.0.0"},'
                '"node_modules/app/node_modules/left-pad":{"version":"1.2.0"}'
                '}}',
                encoding="utf-8",
            )
            bom = generate(path)
            self.assertEqual(
                [(component["name"], component["version"]) for component in bom["components"]],
                [
                    ("@scope/tool", "2.0.0"),
                    ("left-pad", "1.3.0"),
                    ("left-pad", "1.2.0"),
                ],
            )

    def test_package_lock_rejects_malformed_schema_without_crashing(self):
        # A malformed lockfile must fail closed instead of reaching
        # ``.items()`` or sorting with a non-string name and raising a
        # traceback from the SBOM command.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "package-lock.json"
            output = Path(tmp) / "sbom.json"
            for payload, message in (
                ("[]", "must be a JSON object"),
                ('{"packages":[]}', "packages must be an object"),
                ('{"packages":{"node_modules/bad":{"name":{"invalid":true}}}}', "name must be a string"),
                ('{"dependencies":[]}', "dependencies must be an object"),
            ):
                path.write_text(payload, encoding="utf-8")
                with self.subTest(payload=payload):
                    with self.assertRaisesRegex(ValueError, message):
                        generate(path)
                    self.assertEqual(main([str(path), "--output", str(output)]), 2)
                    self.assertFalse(output.exists())

    def test_cli_reports_non_utf8_requirements_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            output = Path(tmp) / "sbom.json"
            path.write_bytes(b"foo==1.0\n\xff\xfe")
            exit_code = main([str(path), "--output", str(output)])
            self.assertEqual(exit_code, 2)
            self.assertFalse(output.exists())

    def test_deep_nested_dependencies_are_walked_without_recursion_error(self):
        # A generated v1 lockfile can contain a dependency chain deeper than
        # Python's recursion limit.  Keep the traversal iterative so valid
        # components are still emitted instead of aborting the SBOM build.
        depth = 1500
        dependencies = {}
        for index in range(depth - 1, -1, -1):
            dependencies = {
                "package-%d" % index: {
                    "version": "1.0.0",
                    "dependencies": dependencies,
                }
            }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "package-lock.json"
            path.write_text("{}", encoding="utf-8")
            with patch(
                "swbom.json.loads",
                return_value={"lockfileVersion": 1, "dependencies": dependencies},
            ):
                components = parse_package_lock(path)
        self.assertEqual(len(components), depth)
        self.assertEqual(components[0]["name"], "package-0")

    def test_cli_reports_deeply_nested_json_without_traceback(self):
        # Malformed deeply nested JSON may fail inside ``json.loads`` itself;
        # the CLI should return its regular input-error status.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "package-lock.json"
            output = Path(tmp) / "sbom.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            self.assertEqual(main([str(path), "--output", str(output)]), 2)
            self.assertFalse(output.exists())

    def test_cli_escapes_lone_surrogate_package_names(self):
        # Lockfiles are external JSON.  An escaped surrogate in a package
        # name must not crash UTF-8 report generation.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "package-lock.json"
            output = Path(tmp) / "sbom.json"
            path.write_text(
                '{"lockfileVersion": 3, "packages": {'
                '"node_modules/example": {"name": "\\ud800", "version": "1.0.0"}'
                '}}',
                encoding="utf-8",
            )

            exit_code = main([str(path), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            report_bytes = output.read_bytes()
            self.assertIn(b"\\ud800", report_bytes)
            self.assertNotIn(b"\xef\xbf\xbd", report_bytes)

if __name__=="__main__": unittest.main()
