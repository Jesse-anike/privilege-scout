import os
import stat
import tempfile
import unittest
from pathlib import Path

from main import scan_directory


class PrivilegeScoutTests(unittest.TestCase):
    def test_detects_suid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "demo"
            target.write_text("synthetic test file", encoding="utf-8")
            target.chmod(0o4755)
            result = scan_directory(root)
            self.assertEqual(result["files_with_privileged_bits"], 1)
            self.assertTrue(result["findings"][0]["suid"])
            self.assertFalse(result["findings"][0]["sgid"])

    def test_detects_sgid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "shared-demo"
            target.write_text("synthetic test file", encoding="utf-8")
            target.chmod(0o2755)
            result = scan_directory(root)
            self.assertEqual(result["sgid_count"], 1)
            self.assertTrue(result["findings"][0]["sgid"])

    def test_ignores_normal_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ordinary.txt").write_text("normal", encoding="utf-8")
            result = scan_directory(root)
            self.assertEqual(result["files_with_privileged_bits"], 0)
            self.assertEqual(result["findings"], [])

    def test_rejects_file_as_scan_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "not-a-directory"
            file_path.write_text("x", encoding="utf-8")
            with self.assertRaises(NotADirectoryError):
                scan_directory(file_path)


if __name__ == "__main__":
    unittest.main()
