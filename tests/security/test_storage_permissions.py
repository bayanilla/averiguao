"""Filesystem exposure of the local database (inventory, approvals, findings and raw evidence)."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from averiguao_core.store import Store


@unittest.skipIf(os.name != "posix", "POSIX permissions only")
class DatabasePermissions(unittest.TestCase):
    def test_database_not_readable_by_other_local_users(self):
        """ISSUE (file permissions): Store() creates the data directory with mkdir() and the SQLite file
        (plus -wal/-shm) with the process umask, so under the usual umask 022 the directory is 0755 and the
        database 0644: any other account on the machine can read the inventory, approval references, org
        names and every finding, although server.py treats these as sensitive (requests are never logged).
        EXPECTED: the data directory is created 0700 and the database files are 0600 (no group/other bits),
        regardless of umask."""
        old = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                data_dir = Path(tmp) / ".averiguao"
                store = Store(data_dir / "averiguao.sqlite3")
                store.runs()
                exposed = {}
                for path in [data_dir, *data_dir.iterdir()]:
                    mode = stat.S_IMODE(path.stat().st_mode)
                    if mode & 0o077:
                        exposed[path.name] = oct(mode)
                self.assertEqual(exposed, {}, "group/other permission bits on the database directory/files")
        finally:
            os.umask(old)


if __name__ == "__main__":
    unittest.main()
