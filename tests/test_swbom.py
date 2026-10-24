import tempfile
import unittest
from pathlib import Path
from swbom import generate

class SbomTests(unittest.TestCase):
    def test_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"requirements.txt"; path.write_text("foo==1.0\n# comment\nbar>=2\n",encoding="utf-8")
            bom=generate(path); self.assertEqual([c["name"] for c in bom["components"]],["bar","foo"])
if __name__=="__main__": unittest.main()
