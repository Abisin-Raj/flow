"""
Unit tests for process attribution and whitelisting functionality.
"""
import pytest
import unittest
from unittest.mock import patch, mock_open, MagicMock
from core import settings_api
from core.collectors import (
    find_pid_for_connection,
    get_proc_name_from_pid,
    create_attributed_alert,
)


class TestProcessAttribution(unittest.TestCase):
    """Test PID lookup and process name resolution."""

    @patch("subprocess.check_output")
    def test_find_pid_via_ss(self, mock_subprocess):
        """Test PID lookup using ss command."""
        # Mock ss output
        mock_subprocess.return_value = """
ESTAB  0  0  127.0.0.1:12345  8.8.8.8:80  users:(("chrome",pid=1234,fd=42))
        """.strip()
        
        pid = find_pid_for_connection("127.0.0.1", "12345", "8.8.8.8", "80")
        self.assertEqual(pid, 1234)

    @patch("subprocess.check_output")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.listdir")
    @patch("os.readlink")
    def test_find_pid_via_proc_fallback(self, mock_readlink, mock_listdir, mock_file, mock_subprocess):
        """Test PID lookup using /proc/net/tcp fallback."""
        # Make ss fail
        mock_subprocess.side_effect = Exception("ss not found")
        
        # Mock /proc/net/tcp with hex-encoded connection
        # 127.0.0.1:12345 (0100007F:3039) -> 8.8.8.8:80 (08080808:0050)
        mock_file.return_value.__enter__.return_value.readlines.return_value = [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            "   0: 0100007F:3039 08080808:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1\n"
        ]
        
        # Mock /proc filesystem
        mock_listdir.side_effect = [
            ["1234", "not_a_pid", "5678"],  # /proc listing
            ["0", "1", "42"],  # /proc/1234/fd
        ]
        
        mock_readlink.side_effect = [
            "socket:[12345]",  # /proc/1234/fd/42 -> socket with matching inode
        ]
        
        pid = find_pid_for_connection("127.0.0.1", "12345", "8.8.8.8", "80")
        self.assertEqual(pid, 1234)

    @patch("os.readlink")
    def test_get_proc_name_from_exe(self, mock_readlink):
        """Test getting process name from /proc/{pid}/exe."""
        mock_readlink.return_value = "/usr/bin/chrome"
        
        name = get_proc_name_from_pid(1234)
        self.assertEqual(name, "chrome")

    @patch("os.readlink")
    @patch("builtins.open", new_callable=mock_open, read_data="antigravity\n")
    def test_get_proc_name_from_comm_fallback(self, mock_file, mock_readlink):
        """Test getting process name from /proc/{pid}/comm when exe fails."""
        mock_readlink.side_effect = OSError("Permission denied")
        
        name = get_proc_name_from_pid(1234)
        self.assertEqual(name, "antigravity")

    def test_get_proc_name_returns_none_for_invalid_pid(self):
        """Test that invalid PIDs return None gracefully."""
        name = get_proc_name_from_pid(None)
        self.assertIsNone(name)


@pytest.mark.django_db
class TestProcessWhitelisting(unittest.TestCase):
    """Test process whitelist configuration and matching."""

    def setUp(self):
        """Set up test environment."""
        # Create a temporary test setting
        from core.models import AppSetting
        AppSetting.objects.filter(key="ignored_processes").delete()

    def tearDown(self):
        """Clean up test environment."""
        from core.models import AppSetting
        AppSetting.objects.filter(key="ignored_processes").delete()

    def test_set_and_get_ignored_processes(self):
        """Test setting and retrieving ignored processes list."""
        test_list = ["chrome", "antigravity", "code"]
        settings_api.set_ignored_processes(test_list)
        
        result = settings_api.get_ignored_processes()
        self.assertEqual(set(result), set(test_list))

    def test_set_ignored_processes_from_csv_string(self):
        """Test setting processes from comma-separated string."""
        settings_api.set_ignored_processes("chrome, antigravity , code")
        
        result = settings_api.get_ignored_processes()
        self.assertEqual(set(result), {"chrome", "antigravity", "code"})

    def test_is_process_ignored_case_insensitive(self):
        """Test that process name matching is case-insensitive."""
        settings_api.set_ignored_processes(["AntiGravity", "Chrome"])
        
        self.assertTrue(settings_api.is_process_ignored_name("antigravity"))
        self.assertTrue(settings_api.is_process_ignored_name("CHROME"))
        self.assertTrue(settings_api.is_process_ignored_name("AntiGravity"))
        self.assertFalse(settings_api.is_process_ignored_name("firefox"))

    def test_is_process_ignored_handles_empty_input(self):
        """Test that empty/None input doesn't crash."""
        settings_api.set_ignored_processes(["chrome"])
        
        self.assertFalse(settings_api.is_process_ignored_name(""))
        self.assertFalse(settings_api.is_process_ignored_name(None))

    def test_get_ignored_processes_handles_missing_setting(self):
        """Test that missing DB entry returns empty list."""
        from core.models import AppSetting
        AppSetting.objects.filter(key="ignored_processes").delete()
        
        result = settings_api.get_ignored_processes()
        self.assertEqual(result, [])


@pytest.mark.django_db
class TestAttributedAlertCreation(unittest.TestCase):
    """Test the create_attributed_alert wrapper."""

    def setUp(self):
        """Set up test environment."""
        from core.models import AppSetting
        AppSetting.objects.filter(key="ignored_processes").delete()
        settings_api.set_ignored_processes(["antigravity"])

    @patch("core.collectors.find_pid_for_connection")
    @patch("core.collectors.get_proc_name_from_pid")
    @patch("core.alert_engine.create_alert_for_connection")
    def test_alert_skipped_for_ignored_process(self, mock_create, mock_get_name, mock_find_pid):
        """Test that alerts are skipped for whitelisted processes."""
        mock_find_pid.return_value = 1234
        mock_get_name.return_value = "antigravity"
        
        result = create_attributed_alert(
            "192.168.1.10", "12345", "8.8.8.8", "80",
            message="Test alert",
            severity="high"
        )
        
        # Alert should be skipped (return None)
        self.assertIsNone(result)
        # create_alert_for_connection should NOT be called
        mock_create.assert_not_called()

    @patch("core.collectors.find_pid_for_connection")
    @patch("core.collectors.get_proc_name_from_pid")
    @patch("core.alert_engine.create_alert_for_connection")
    def test_alert_created_for_non_ignored_process(self, mock_create, mock_get_name, mock_find_pid):
        """Test that alerts are created for non-whitelisted processes."""
        mock_find_pid.return_value = 1234
        mock_get_name.return_value = "malware"
        mock_create.return_value = MagicMock()  # Mock alert object
        
        result = create_attributed_alert(
            "192.168.1.10", "12345", "8.8.8.8", "80",
            message="Test alert",
            severity="high"
        )
        
        # Alert should be created
        self.assertIsNotNone(result)
        # create_alert_for_connection should be called with proc_name
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args[1]
        self.assertEqual(call_kwargs["proc_name"], "malware")

    @patch("core.collectors.find_pid_for_connection")
    @patch("core.collectors.get_proc_name_from_pid")
    @patch("core.alert_engine.create_alert_for_connection")
    def test_alert_created_when_pid_not_found(self, mock_create, mock_get_name, mock_find_pid):
        """Test that alerts are created when PID cannot be determined."""
        mock_find_pid.return_value = None
        mock_get_name.return_value = None
        mock_create.return_value = MagicMock()
        
        result = create_attributed_alert(
            "192.168.1.10", "12345", "8.8.8.8", "80",
            message="Test alert",
            severity="high"
        )
        
        # Alert should still be created (we can't determine if it's safe)
        self.assertIsNotNone(result)
        mock_create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
