"""B9: what the Memurai setup insists on, checked without needing Memurai.

`scripts/memurai_setup.py` is the install/configure/health/uninstall path a customer
deployment follows, and the decisions in it are the ones §5 of the plan made: loopback
only, a password beside the vault key, a confined ACL user, a small memory cap with no
eviction, and nothing persisted to disk.

These pin the policy - the ACL rules and the settings the health check demands - so a
later edit that quietly loosens one fails here. `tests/test_memurai_live.py` runs the
same script's health check against a real server when one is configured.
"""

from __future__ import annotations

import unittest

from scripts import memurai_setup


class TheAclIsLeastPrivilegeTest(unittest.TestCase):

    def test_it_starts_from_no_commands_at_all(self) -> None:
        self.assertIn("-@all", memurai_setup.ACL_RULES)
        self.assertLess(memurai_setup.ACL_RULES.index("-@all"),
                        memurai_setup.ACL_RULES.index("+@read"),
                        "a later rule wins, so the denial has to come first")

    def test_the_dangerous_commands_are_taken_back_after_the_categories_that_include_them(self) -> None:
        rules = list(memurai_setup.ACL_RULES)
        self.assertIn("-@dangerous", rules)
        self.assertGreater(rules.index("-@dangerous"), rules.index("+@read"),
                           "@read grants KEYS, which would list every key in the server")
        self.assertGreater(rules.index("+info"), rules.index("-@dangerous"),
                           "INFO is classed as dangerous and the health check needs it")

    def test_the_user_is_confined_to_the_products_own_keys(self) -> None:
        self.assertIn("resetkeys", memurai_setup.ACL_RULES)
        self.assertIn(f"~{memurai_setup.KEY_PREFIX}*", memurai_setup.ACL_RULES)

    def test_it_never_grants_administration(self) -> None:
        for granted in memurai_setup.ACL_RULES:
            with self.subTest(rule=granted):
                self.assertNotIn(granted, ("+@admin", "+@dangerous", "+config", "+keys", "+flushall", "+flushdb"))


class TheSettingsAreThePlansTest(unittest.TestCase):

    def test_nothing_listens_off_this_host(self) -> None:
        self.assertEqual(memurai_setup.REQUIRED_SETTINGS["bind"], "127.0.0.1")

    def test_nothing_is_evicted(self) -> None:
        self.assertEqual(memurai_setup.REQUIRED_SETTINGS["maxmemory-policy"], "noeviction")

    def test_nothing_is_persisted(self) -> None:
        self.assertEqual(memurai_setup.REQUIRED_SETTINGS["appendonly"], "no")
        self.assertEqual(memurai_setup.REQUIRED_SETTINGS["save"], "",
                         "everything in Memurai is reconstructible from PostgreSQL")

    def test_memory_is_capped_small(self) -> None:
        self.assertEqual(memurai_setup.MAX_MEMORY, "256mb")


class TheSecretIsHandledLikeAKeyTest(unittest.TestCase):

    def test_it_lives_beside_the_vault_key(self) -> None:
        self.assertEqual(memurai_setup.SECRET_PATH.parent.name, ".dspm")

    def test_the_password_is_never_printed(self) -> None:
        import inspect

        source = inspect.getsource(memurai_setup)
        for line in source.splitlines():
            if "_print(" in line and "secret" in line.lower():
                with self.subTest(line=line.strip()[:70]):
                    self.assertNotIn("{secret}", line, "a health report must not put the password in a log")


if __name__ == "__main__":
    unittest.main()
