"""The test suite never opens the developer's own database.

Importing ``backend.store`` converges the schema of whatever database ``DSPM_DB_PATH``
names at that moment. The suite's conftest imported the store one line before it chose
the session database, so every run migrated ``data/dspm.sqlite`` - and a backend left
running on older code then found its database at a revision it did not know (applied 17,
expected 10), reported itself not ready, and the Remediation page could not load.
"""

from __future__ import annotations

import unittest

from backend import db, store
from tests import conftest


class TheSuiteLeavesTheRealDatabaseAloneTest(unittest.TestCase):

    def test_the_store_was_first_opened_on_the_session_database(self) -> None:
        if db.is_postgres() or conftest.STORE_IMPORTED_WITH is None:
            self.skipTest("the SQLite session database is not in use (PostgreSQL, or DSPM_TEST_KEEP_DB)")
        real = (store.DATA_DIR / "dspm.sqlite").resolve()
        self.assertNotEqual(conftest.STORE_IMPORTED_WITH.resolve(), real,
                            "importing the store opened - and migrated - the developer's database")


if __name__ == "__main__":
    unittest.main()
