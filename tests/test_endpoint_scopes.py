import unittest

from collectors.file_scanner import matches_scan_filters
from collectors.winrm_endpoint_scanner import (
    ENDPOINT_PATH_ALIASES,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    _scan_script,
    normalize_endpoint_target_paths,
)


class EndpointScopeTests(unittest.TestCase):
    def test_extension_filter_does_not_include_system_files_by_default(self):
        self.assertFalse(
            matches_scan_filters(
                ".ini",
                is_hidden=False,
                is_system=True,
                extension_filter={".ini"},
                extension_filter_enabled=True,
                include_hidden=True,
                include_system=False,
                hidden_filter_enabled=False,
                system_filter_enabled=False,
            )
        )

    def test_system_filter_explicitly_finds_system_files_with_extension_filter(self):
        self.assertTrue(
            matches_scan_filters(
                ".ini",
                is_hidden=False,
                is_system=True,
                extension_filter={".ini"},
                extension_filter_enabled=True,
                include_hidden=True,
                include_system=False,
                hidden_filter_enabled=False,
                system_filter_enabled=True,
            )
        )

    def test_endpoint_aliases_expand_to_bounded_data_scopes(self):
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(
                host="endpoint-01",
                username="admin",
                password="secret",
                target_username="dspm.scan",
                paths=["downloads", "all", "c_drive", "all_fixed_drives"],
            )
        )

        self.assertEqual(
            scanner._target_paths(),
            [
                "__DSPM_PROFILE_FOLDER_FOR__:dspm.scan:Downloads",
                "__DSPM_PROFILE_ROOT_FOR__:dspm.scan",
                "C:\\",
                "__DSPM_FIXED_DRIVES__",
            ],
        )

    def test_all_endpoint_aliases_use_shared_target_path_normalization(self):
        self.assertEqual(
            ENDPOINT_PATH_ALIASES,
            {"desktop", "documents", "downloads", "profile_standard", "all", "all_profiles", "c_drive", "onedrive", "all_fixed_drives"},
        )
        self.assertEqual(
            normalize_endpoint_target_paths(
                [
                    "desktop",
                    "documents",
                    "downloads",
                    "profile_standard",
                    "all",
                    "all_profiles",
                    "c_drive",
                    "onedrive",
                    "all_fixed_drives",
                    "Projects\\Secure",
                ],
                "test.user01",
            ),
            [
                "__DSPM_PROFILE_FOLDER_FOR__:test.user01:Desktop",
                "__DSPM_PROFILE_FOLDER_FOR__:test.user01:Documents",
                "__DSPM_PROFILE_FOLDER_FOR__:test.user01:Downloads",
                "__DSPM_PROFILE_STANDARD_FOR__:test.user01",
                "__DSPM_PROFILE_ROOT_FOR__:test.user01",
                "__DSPM_ALL_PROFILES__",
                "C:\\",
                "__DSPM_ONEDRIVE_FOR__:test.user01",
                "__DSPM_FIXED_DRIVES__",
                "__DSPM_PROFILE_RELATIVE_FOR__:test.user01:Projects\\Secure",
            ],
        )

    def test_custom_absolute_paths_are_normalized_without_profile_rewrite(self):
        self.assertEqual(
            normalize_endpoint_target_paths(["C:/Users/test.user01/Downloads", r"\\fileserver\share"], "test.user01"),
            [r"C:\Users\test.user01\Downloads", r"\\fileserver\share"],
        )

    def test_profile_match_accepts_common_windows_profile_variants(self):
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="endpoint-01", username="admin", password="secret", target_username="dspm")
        )

        self.assertTrue(scanner._path_matches_target_profile(r"C:\Users\dspm\Downloads\a.txt"))
        self.assertTrue(scanner._path_matches_target_profile(r"C:\Users\dspm.scan\Downloads\a.txt"))
        self.assertTrue(scanner._path_matches_target_profile(r"C:\Users\dspm_000\Downloads\a.txt"))
        self.assertFalse(scanner._path_matches_target_profile(r"C:\Users\other\Downloads\a.txt"))

    def test_generated_winrm_script_uses_profile_data_roots_for_wide_scopes(self):
        script = _scan_script(
            ["__DSPM_ALL_PROFILES__", "__DSPM_FIXED_DRIVES__", "C:\\"],
            max_depth=3,
            read_content=True,
            max_read_bytes=1024,
            allowed_extensions=[".ini"],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=False,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
            read_acl=False,
            inspect_archives=False,
        )

        self.assertIn("$roots.Add($_.FullName) | Out-Null", script)
        self.assertIn("$roots.Add($driveRoot) | Out-Null", script)
        self.assertIn("'\\appdata\\'", script)
        self.assertIn("'\\$recycle.bin\\'", script)
        self.assertIn("__DSPM_PROFILE_RELATIVE_FOR__:", script)
        self.assertIn("(-not $false) -and $isSystem -and -not $false", script)


if __name__ == "__main__":
    unittest.main()
