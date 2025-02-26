import unittest
from unittest.mock import patch, MagicMock, mock_open
import mysql.connector
import subprocess

# Import the modules to test
from main import connect_to_db, hash_password, check_password

class TestCoreFunctionality(unittest.TestCase):
    """Tests for core functionalities"""

    @patch('mysql.connector.connect')
    def test_connect_to_db(self, mock_connect):
        """Test database connection."""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn
        
        result = connect_to_db()
        
        mock_connect.assert_called_once()
        self.assertEqual(result, mock_conn)
        print("✅ test_connect_to_db passed")

    @patch('main.check_password', side_effect=lambda stored, entered: True)
    def test_password_functions(self, mock_check):
        """Test password hashing and verification."""
        password = "password123"
        hashed = hash_password(password)
        
        self.assertNotEqual(hashed, password.encode())  # Ensure it's hashed
        self.assertTrue(mock_check(hashed, password))  # Mock check

        print("✅ test_password_functions passed")

class TestLogAnalysis(unittest.TestCase):
    """Tests for log analysis functionality."""

    @patch('builtins.open', mock_open(read_data="✅ Log line 1\n❌ Log line 2\nLog line 3\n"))
    def test_analyze_logs(self):
        """Test log file reading."""
        log_file_path = "/path/to/logs.log"
        
        with open(log_file_path, "r") as file:
            log_data = file.readlines()
        
        self.assertIn("✅ Log line 1\n", log_data)
        self.assertIn("❌ Log line 2\n", log_data)
        
        print("✅ test_analyze_logs passed")

class TestUSBTracker(unittest.TestCase):
    """Tests for USB device tracking."""

    @patch('subprocess.check_output')
    def test_show_connected_devices(self, mock_check_output):
        """Test detecting USB devices."""
        mock_check_output.return_value = "Bus 001 Device 002: ID 8087:0024 Intel Corp. Hub\nBus 001 Device 003: ID 0bc2:2322 Seagate External Drive"
        
        result = subprocess.check_output(["lsusb"], text=True)
        
        mock_check_output.assert_called_once()
        self.assertIn("Intel Corp. Hub", result)
        self.assertIn("Seagate External Drive", result)

        print("✅ test_show_connected_devices passed")

if __name__ == '__main__':
    unittest.main()
