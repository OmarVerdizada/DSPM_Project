"""C11: one validated configuration source.

Gate lines: "deterministic validated config (schema, prod/dev modes, env override
precedence, unsafe production combinations fail)" and "no secret may appear in ... API
config reads, service command lines". The file is TOML, the environment wins over it and
it over the defaults, a misspelt name is refused, secrets come from files named by
`<NAME>_FILE` and are never printed, and production refuses what would weaken it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from backend import config

ROOT = Path(__file__).resolve().parents[1]

# What a production install needs, as files (the installer writes these).
_SECRETS = {
    "DSPM_SECRET_KEY": "jwt-secret-" + "k" * 40,
    "DSPM_VAULT_KEY": "vault-key-" + "v" * 34,
    "DSPM_ARTIFACT_KEY": "artifact-key-" + "a" * 31,
    "DSPM_BACKUP_KEY": "backup-key-" + "b" * 33,
    "DSPM_EVIDENCE_HMAC_KEY": "evidence-key-" + "e" * 30,
    "DSPM_ADMIN_PASSWORD": "Kestrel-admin-pass-4471",
    "DSPM_DB_URL": "postgresql://sentro_app:db-pass-9922@127.0.0.1:5432/sentro",
}


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def write(self, text: str, name: str = "sentro.toml") -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def secret_files(self) -> str:
        lines = []
        for name, value in _SECRETS.items():
            path = self.tmp / name.lower()
            path.write_text(value + "\n", encoding="utf-8")
            lines.append(f"{name}_FILE = '{path}'")
        return "\n".join(lines)

    def production_file(self, extra: str = "") -> Path:
        # A backup directory of its own: `config check` refuses production beside a
        # plaintext dump there (C0.2), and the checkout's data/backups may hold one.
        backups = f"DSPM_BACKUP_DIR = '{self.tmp / 'backups'}'\n"
        return self.write("[settings]\nDSPM_ENV = \"production\"\n" + self.secret_files() + "\n" + backups + extra)


class PrecedenceTest(_Case):

    def test_environment_then_file_then_default(self) -> None:
        path = self.write('[settings]\nDSPM_TOKEN_TTL_SECONDS = 900\nDSPM_SESSION_IDLE_SECONDS = 1200\n')
        effective = config.resolve({"DSPM_TOKEN_TTL_SECONDS": "600"}, path)
        self.assertEqual(effective.errors, [])
        self.assertEqual((effective.get("DSPM_TOKEN_TTL_SECONDS"), effective.values["DSPM_TOKEN_TTL_SECONDS"].source),
                         ("600", "environment"))
        self.assertEqual((effective.get("DSPM_SESSION_IDLE_SECONDS"), effective.values["DSPM_SESSION_IDLE_SECONDS"].source),
                         ("1200", "file"))
        self.assertEqual((effective.get("DSPM_LOG_MAX_MB"), effective.values["DSPM_LOG_MAX_MB"].source), ("10", "default"))

    def test_the_same_inputs_resolve_the_same_way(self) -> None:
        path = self.write('[settings]\nDSPM_PARTITIONED_SCANS = true\nDSPM_JOB_WORKERS = 3\n')
        first = config.resolve({"DSPM_ENV": "local"}, path)
        second = config.resolve({"DSPM_ENV": "local"}, path)
        self.assertEqual(first.describe(show_defaults=True), second.describe(show_defaults=True))

    def test_apply_fills_only_what_the_environment_lacks_and_normalises_switches(self) -> None:
        path = self.write('[settings]\nDSPM_PARTITIONED_SCANS = true\nDSPM_JOB_WORKERS = 3\nDSPM_OCR_ENABLED = "yes"\n')
        environ = {"DSPM_JOB_WORKERS": "5", "DSPM_SQLITE_HOLD_OPEN": "true"}
        config.bootstrap(path, environ)
        self.assertEqual(environ["DSPM_JOB_WORKERS"], "5", "the environment wins")
        self.assertEqual(environ["DSPM_PARTITIONED_SCANS"], "1", "true/false become the 1/0 every reader expects")
        self.assertEqual(environ["DSPM_OCR_ENABLED"], "1")
        self.assertEqual(environ["DSPM_SQLITE_HOLD_OPEN"], "1")
        self.assertEqual(environ[config.CONFIG_ENV], str(path))


class ValidationTest(_Case):

    def test_a_misspelt_name_in_the_file_is_refused(self) -> None:
        path = self.write('[settings]\nDSPM_SESION_IDLE_SECONDS = 600\n')
        with self.assertRaises(config.ConfigError) as refused:
            config.bootstrap(path, {})
        self.assertIn("DSPM_SESION_IDLE_SECONDS is not a Sentro setting", str(refused.exception))

    def test_types_ranges_and_choices_are_checked(self) -> None:
        for text, fragment in (('DSPM_TOKEN_TTL_SECONDS = "soon"', "whole number"),
                               ("DSPM_PBKDF2_ROUNDS = 1000", "at least 210000"),
                               ('DSPM_SCAN_EXECUTION = "threads"', "one of inline, queue"),
                               ('DSPM_PARTITIONED_SCANS = "maybe"', "1 or 0"),
                               ('DSPM_ENV = "staging"', "DSPM_ENV must be one of")):
            with self.subTest(text=text):
                effective = config.resolve({}, self.write(f"[settings]\n{text}\n"))
                self.assertTrue(any(fragment in error for error in effective.errors), effective.errors)

    def test_only_a_settings_table_is_read(self) -> None:
        effective = config.resolve({}, self.write('[server]\nport = 8000\n'))
        self.assertTrue(any("only a [settings] table" in error for error in effective.errors))

    def test_broken_toml_names_the_file(self) -> None:
        path = self.write('[settings]\nDSPM_ENV = "production\n')
        effective = config.resolve({}, path)
        self.assertTrue(any(str(path) in error and "not valid TOML" in error for error in effective.errors))

    def test_an_unknown_name_in_the_environment_is_a_warning_not_a_refusal(self) -> None:
        effective = config.resolve({"DSPM_TOTALLY_NEW": "1"}, None)
        self.assertEqual(effective.errors, [])
        self.assertTrue(any("DSPM_TOTALLY_NEW" in warning for warning in effective.warnings))

    def test_a_removed_setting_says_what_replaced_it(self) -> None:
        effective = config.resolve({"DSPM_ALLOW_PRIVATE_TARGETS": "1"}, None)
        self.assertTrue(any("Scan targets" in warning for warning in effective.warnings))


class SecretsTest(_Case):

    def test_a_secret_is_read_from_the_file_its_FILE_setting_names(self) -> None:
        key_file = self.tmp / "vault.key"
        key_file.write_text("the-vault-key-value\n", encoding="utf-8")
        environ: dict[str, str] = {}
        config.bootstrap(self.write(f"[settings]\nDSPM_VAULT_KEY_FILE = '{key_file}'\n"), environ)
        self.assertEqual(environ["DSPM_VAULT_KEY"], "the-vault-key-value")

    def test_a_secret_written_into_the_file_is_refused_in_production_and_warned_otherwise(self) -> None:
        local = config.resolve({}, self.write('[settings]\nDSPM_VAULT_KEY = "inline-key"\n'))
        self.assertEqual(local.errors, [])
        self.assertTrue(any("does not belong in the configuration file" in w for w in local.warnings))
        production = config.resolve({}, self.production_file('DSPM_BACKUP_DB_URL = "postgresql://b:pw@h/db"'))
        self.assertTrue(any("DSPM_BACKUP_DB_URL is a secret" in e for e in production.errors), production.errors)

    def test_an_unreadable_or_empty_secret_file_is_an_error(self) -> None:
        empty = self.tmp / "empty.key"
        empty.write_text("   \n", encoding="utf-8")
        missing = self.tmp / "nowhere.key"
        effective = config.resolve({}, self.write(
            f"[settings]\nDSPM_VAULT_KEY_FILE = '{empty}'\nDSPM_BACKUP_KEY_FILE = '{missing}'\n"))
        self.assertTrue(any("empty" in error for error in effective.errors))
        self.assertTrue(any("cannot be read" in error for error in effective.errors))

    def test_the_description_never_shows_a_secret(self) -> None:
        effective = config.resolve({}, self.production_file())
        self.assertEqual(effective.errors, [])
        text = repr(effective.describe(show_defaults=True))
        for value in _SECRETS.values():
            self.assertNotIn(value, text)
        self.assertIn(("DSPM_VAULT_KEY", "(set)"), [(row[0], row[1]) for row in effective.describe()])

    def test_config_check_prints_sources_and_no_secret(self) -> None:
        path = self.production_file()
        completed = subprocess.run([sys.executable, str(ROOT / "main.py"), "--config", str(path), "config", "check"],
                                   cwd=ROOT, capture_output=True, encoding="utf-8", errors="replace",
                                   env={"SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
                                        "PATH": __import__("os").environ.get("PATH", "")})
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        for value in _SECRETS.values():
            self.assertNotIn(value, completed.stdout + completed.stderr)
        self.assertRegex(completed.stdout, r"DSPM_VAULT_KEY\s+\(set\)\s+secret file")
        self.assertIn("configuration is valid", completed.stdout)


class ProductionTest(_Case):

    def test_a_complete_production_file_is_valid(self) -> None:
        effective = config.resolve({}, self.production_file())
        self.assertEqual(effective.errors, [])
        self.assertTrue(effective.production)

    def test_each_weakening_switch_is_refused(self) -> None:
        for line, fragment in (("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS = 1", "unsalted SHA-256"),
                               ("DSPM_SYNC_BUILTIN_ADMIN = true", "resets the administrator"),
                               ("DSPM_WINRM_SSL_SKIP_CA_CHECK = 1", "without checking their certificate"),
                               ("DSPM_PLAINTEXT_REPORT_EXPORT = 1", "plaintext copies"),
                               ("DSPM_ALLOW_DL_TOKEN_QUERY = 1", "download tokens in URLs"),
                               ('DSPM_CORS_ORIGINS = "*"', "DSPM_CORS_ORIGINS=*"),
                               ("DSPM_PG_TEST_RESET = 1", "test-suite switch")):
            with self.subTest(line=line):
                effective = config.resolve({}, self.production_file(line))
                self.assertTrue(any(fragment in error for error in effective.errors), effective.errors)
                with self.assertRaises(config.ConfigError):
                    config.bootstrap(effective.path, {})

    def test_the_same_switches_are_allowed_outside_production(self) -> None:
        effective = config.resolve({}, self.write("[settings]\nDSPM_SYNC_BUILTIN_ADMIN = 1\nDSPM_WINRM_SSL_SKIP_CA_CHECK = 1\n"))
        self.assertEqual(effective.errors, [])

    def test_missing_keys_are_named(self) -> None:
        effective = config.resolve({}, self.write('[settings]\nDSPM_ENV = "production"\n'))
        for name in ("DSPM_SECRET_KEY", "DSPM_VAULT_KEY", "DSPM_ARTIFACT_KEY", "DSPM_BACKUP_KEY",
                     "DSPM_EVIDENCE_HMAC_KEY", "DSPM_ADMIN_PASSWORD", "DSPM_DB_URL"):
            self.assertTrue(any(error.startswith(name) for error in effective.errors), name)

    def _with_db_url(self, value: str) -> config.Effective:
        url = self.tmp / "remote_url"
        url.write_text(value, encoding="utf-8")
        text = self.production_file().read_text(encoding="utf-8").replace(
            str(self.tmp / "dspm_db_url"), str(url))
        return config.resolve({}, self.write(text, "remote.toml"))

    def test_a_remote_database_without_a_verified_certificate_is_refused(self) -> None:
        # No sslmode is libpq's "prefer" (plaintext when refused); "require" takes any
        # certificate; a host in the query string is as remote as one in the authority.
        for url in ("postgresql://app:pw@db01.corp.example:5432/sentro?sslmode=disable",
                    "postgresql://app:pw@db01.corp.example:5432/sentro",
                    "postgresql://app:pw@db01.corp.example:5432/sentro?sslmode=require",
                    "postgresql://app:pw@/sentro?host=db01.corp.example&sslmode=disable",
                    "postgresql://app:pw@127.0.0.1,db02.corp.example/sentro?sslmode=prefer"):
            effective = self._with_db_url(url)
            self.assertTrue(any("without verifying its certificate" in error for error in effective.errors),
                            (url, effective.errors))
            self.assertNotIn("pw@", repr(effective.errors), "the refusal does not quote the URL")

    def test_a_verified_or_local_database_is_accepted(self) -> None:
        for url in ("postgresql://app:pw@db01.corp.example:5432/sentro?sslmode=verify-full&sslrootcert=ca.pem",
                    "postgresql://app:pw@db01.corp.example/sentro?sslmode=verify-ca",
                    "postgresql://app:pw@127.0.0.1:5432/sentro",
                    "postgresql://app:pw@localhost/sentro?sslmode=disable"):
            effective = self._with_db_url(url)
            self.assertFalse(any("certificate" in error for error in effective.errors), (url, effective.errors))

    def test_the_backup_and_migration_urls_are_held_to_the_same_rule(self) -> None:
        secret = self.tmp / "backup_url"
        secret.write_text("postgresql://b:pw@backup.corp.example/sentro?sslmode=require", encoding="utf-8")
        effective = config.resolve({"DSPM_BACKUP_DB_URL_FILE": str(secret)}, self.production_file())
        self.assertTrue(any(error.startswith("DSPM_BACKUP_DB_URL reaches a remote PostgreSQL")
                            for error in effective.errors), effective.errors)

    def test_a_key_ring_replaces_the_single_vault_key(self) -> None:
        ring = self.tmp / "vault_keyring.json"
        ring.write_text("{}", encoding="utf-8")
        text = self.production_file().read_text(encoding="utf-8")
        without_key = "\n".join(line for line in text.splitlines() if not line.startswith("DSPM_VAULT_KEY"))
        without_key += f'\nDSPM_VAULT_KEYRING = "{ring.as_posix()}"\n'
        effective = config.resolve({}, self.write(without_key, "ring.toml"))
        self.assertFalse(any(error.startswith("DSPM_VAULT_KEY ") for error in effective.errors), effective.errors)
        ring.unlink()
        effective = config.resolve({}, self.write(without_key, "ring.toml"))
        self.assertTrue(any(error.startswith("DSPM_VAULT_KEY ") for error in effective.errors),
                        "a ring that does not exist yet is no key at all")

    def test_a_test_suites_key_is_never_shown(self) -> None:
        effective = config.resolve({"DSPM_MEILISEARCH_LIVE_KEY": "meili-live-key-8812"}, None)
        shown = dict((name, value) for name, value, _source in effective.describe())
        self.assertEqual(shown.get("DSPM_MEILISEARCH_LIVE_KEY"), "(set)")
        self.assertIn("meili-live-key-8812", config.secret_values({"DSPM_MEILISEARCH_LIVE_KEY": "meili-live-key-8812"}))

    def test_production_through_the_environment_is_held_to_the_same_rules(self) -> None:
        effective = config.resolve({"DSPM_ENV": "production", "DSPM_SYNC_BUILTIN_ADMIN": "1"}, None)
        self.assertTrue(any("DSPM_SYNC_BUILTIN_ADMIN" in error for error in effective.errors))


class TheCatalogueCoversTheCodeTest(unittest.TestCase):

    def test_every_setting_the_product_reads_is_catalogued(self) -> None:
        tracked = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        names: set[str] = set()
        for rel in tracked:
            if rel.startswith("tests/"):
                continue
            names |= set(re.findall(r"\bDSPM_[A-Z0-9_]+", (ROOT / rel).read_text(encoding="utf-8", errors="replace")))
        self.assertIn("DSPM_VAULT_KEY", names, "the scan must find the names it is about")
        unknown = sorted(name for name in names
                         if name not in config.SETTINGS and name not in config.NOT_SETTINGS
                         and name not in config.TEST_ONLY and not name.endswith("_FILE"))
        self.assertEqual(unknown, [], "read by the product but not in backend/config.SETTINGS")

    def test_every_documented_setting_is_catalogued(self) -> None:
        documented = set(re.findall(r"^#? ?(DSPM_[A-Z0-9_]+)=", (ROOT / ".env.example").read_text(encoding="utf-8"), re.M))
        unknown = sorted(name for name in documented if not config._known(name) and name not in config.NOT_SETTINGS)
        self.assertEqual(unknown, [])

    def test_every_default_the_code_uses_passes_the_schema(self) -> None:
        pattern = re.compile(r'(?:getenv|environ\.get)\(\s*"(DSPM_[A-Z0-9_]+)"\s*,\s*"([^"]*)"')
        tracked = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        wrong = []
        for rel in tracked:
            if rel.startswith("tests/"):
                continue
            for name, default in pattern.findall((ROOT / rel).read_text(encoding="utf-8", errors="replace")):
                setting = config.SETTINGS.get(name)
                if setting and setting.kind not in {"secret", "path", "str"}:
                    problem = config._check_value(setting, default)
                    if problem:
                        wrong.append((rel, problem))
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
