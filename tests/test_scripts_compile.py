import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


class ScriptsCompileTests(unittest.TestCase):
    """Syntax gate for every Python operator script.

    Several scripts are Windows-only or only inspected as source text on Linux,
    so nothing else in the deterministic suite would notice a syntax error in
    them. Compiling (not importing) keeps this free of side effects.
    """

    def test_every_python_script_compiles(self):
        scripts = sorted(SCRIPTS_DIR.glob("*.py"))
        self.assertTrue(scripts, "no Python scripts found")
        for path in scripts:
            with self.subTest(script=path.name):
                compile(path.read_bytes(), str(path), "exec", dont_inherit=True)


if __name__ == "__main__":
    unittest.main()
