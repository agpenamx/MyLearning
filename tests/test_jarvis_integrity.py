"""No external dependencies or network calls."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from jarvis_integrity import verify

class TestIntegrity(unittest.TestCase):
    def test_valid_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            f=root/"public.md"
            f.write_text("safe baseline\n", encoding="utf-8")
            b=f.read_bytes()
            sha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
            m=root/"manifest.json"
            m.write_text(json.dumps({"files":{"public.md":sha}}))
            good=verify(root,m)
            self.assertEqual("PASS",good["result"])
            self.assertEqual(128,len(good["fingerprints"][0]["sha3_512"]))
            f.write_text("tampered\n")
            self.assertEqual("FAIL",verify(root,m)["result"])

    def test_missing_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            m=root/"manifest.json"
            m.write_text(json.dumps({"files":{"absent.txt":"0"*40}}))
            self.assertEqual("FAIL",verify(root,m)["result"])
            (root/"absent.txt").symlink_to("/etc/hosts")
            self.assertEqual("FAIL",verify(root,m)["result"])

    def test_secret_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            f=root/"f.txt"
            f.write_text("-----BEGIN PRIVATE KEY-----\n")
            b=f.read_bytes()
            sha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
            m=root/"manifest.json"
            m.write_text(json.dumps({"files":{"f.txt":sha}}))
            self.assertEqual("FAIL",verify(root,m)["result"])

if __name__=="__main__":
    unittest.main()
