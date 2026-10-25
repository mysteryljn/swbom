import tempfile
import unittest
from pathlib import Path
from swbom import generate

class SbomTests(unittest.TestCase):
    def test_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"requirements.txt"; path.write_text("foo==1.0\n# comment\nbar>=2\n",encoding="utf-8")
            bom=generate(path); self.assertEqual([c["name"] for c in bom["components"]],["bar","foo"])

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
if __name__=="__main__": unittest.main()
