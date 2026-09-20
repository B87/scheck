"""Exercise release failure paths without GitHub credentials or target access."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release


class ReleaseTests(unittest.TestCase):
    def test_tags(self):
        for tag in ("v0.0.1", "v1.2.3-rc.1", "v0.0.1-rehearsal.1"):
            self.assertEqual(release.version(tag), tag[1:])
        for tag in ("main", "v01.0.0", "v1.2", "v1.2.3-01", "v1.2.3;echo bad", "v1.2.3\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version(tag)

    def test_existing_release_including_later_page(self):
        for draft in (True, False):
            with self.subTest(draft=draft), self.assertRaises(ValueError):
                release.refuse_existing("v0.0.1", [[], [{"tag_name": "v0.0.1", "draft": draft}]])
        release.refuse_existing("v0.0.1", [[{"tag_name": "v0.0.2"}]])

    def test_preflight_fails_closed(self):
        for replies in (("abc", "def"), ("abc", "abc", " M go.mod")):
            with patch.object(release, "output", side_effect=replies), self.assertRaises(ValueError):
                release.preflight("v0.0.1", "b87/scheck")
        with patch.object(release, "output", side_effect=["abc", "abc", "",
                subprocess.CalledProcessError(1, "gh")]), self.assertRaises(subprocess.CalledProcessError):
            release.preflight("v0.0.1", "b87/scheck")

    def assets(self, directory, extra=False):
        lines = []
        for system in ("linux", "darwin"):
            for arch in ("amd64", "arm64"):
                archive = directory / f"scheck_0.0.1_{system}_{arch}.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    entries = {"scheck": b"binary", "LICENSE": Path("LICENSE").read_bytes()}
                    if extra:
                        entries["../unexpected"] = b"unexpected"
                    for name, data in entries.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        member.mode = 0o755 if name == "scheck" else 0o644
                        tar.addfile(member, io.BytesIO(data))
                lines.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}")
        (directory / "checksums.txt").write_text("\n".join(lines) + "\n")
        return archive

    def test_missing_corrupt_and_unexpected_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = self.assets(directory)
            release.verify_assets("v0.0.1", directory)
            archive.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                release.verify_assets("v0.0.1", directory)
            archive.unlink()
            with self.assertRaisesRegex(ValueError, "exactly four"):
                release.verify_assets("v0.0.1", directory)
            self.assets(directory, extra=True)
            with self.assertRaisesRegex(ValueError, "archive contents"):
                release.verify_assets("v0.0.1", directory)

    def test_native_failure_and_wrong_version(self):
        with patch.object(release, "output", return_value="scheck version dev"), self.assertRaises(ValueError):
            release.smoke_binary(Path("scheck"), "v0.0.1", Path("."))
        with patch.object(release, "output", side_effect=subprocess.CalledProcessError(1, "scheck")), \
                self.assertRaises(subprocess.CalledProcessError):
            release.smoke_binary(Path("scheck"), "v0.0.1", Path("."))
        wrong = json.dumps({"kind": "catalog", "scheck_version": "v0.0.1", "checks": []})
        with patch.object(release, "output", side_effect=["scheck version v0.0.1", wrong]), \
                self.assertRaises(ValueError):
            release.smoke_binary(Path("scheck"), "v0.0.1", Path("."))


if __name__ == "__main__":
    unittest.main()
