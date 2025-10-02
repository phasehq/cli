import unittest
import json
from unittest.mock import patch
from phase_cli.cmd.secrets.get import phase_secrets_get

class TestPhaseSecretsGet(unittest.TestCase):
    
    def setUp(self):
        # Reset all mocks before each test to avoid interference between tests
        self.patcher_console = patch('phase_cli.cmd.secrets.get.Console')
        self.mock_console = self.patcher_console.start()
        self.mock_console_instance = self.mock_console.return_value
        
        self.patcher_phase = patch('phase_cli.cmd.secrets.get.Phase')
        self.mock_phase = self.patcher_phase.start()
        self.mock_phase_instance = self.mock_phase.return_value
        
        self.patcher_exit = patch('phase_cli.cmd.secrets.get.sys.exit')
        self.mock_exit = self.patcher_exit.start()
    
    def tearDown(self):
        # Ensure all patches are properly stopped
        self.patcher_console.stop()
        self.patcher_phase.stop()
        self.patcher_exit.stop()
    
    def test_phase_secrets_get_success(self):
        # Mock the return value to simulate a successful secret fetch
        mock_secret = {
            "key": "TEST_KEY", 
            "value": "test_value", 
            "environment": "dev", 
            "application": "test-app",
            "path": "/"
        }
        self.mock_phase_instance.get.return_value = [mock_secret]
        
        # Spy on print function to verify output
        with patch('builtins.print') as mock_print:
            # Act: Call the function
            phase_secrets_get("TEST_KEY", env_name="dev", phase_app="test-app")
            
            # Assert: Verify the correct output was printed
            mock_print.assert_called_once_with(json.dumps(mock_secret, indent=4))
            
            # Verify sys.exit was not called (function completes normally)
            self.mock_exit.assert_not_called()
            
            # Verify that Phase.get was called with correct args
            self.mock_phase_instance.get.assert_called_once_with(
                env_name="dev", 
                keys=["TEST_KEY"], 
                app_name="test-app", 
                app_id=None, 
                tag=None, 
                path="/",
                dynamic=True,
                lease=True,
                lease_ttl=None
            )
    
    def test_phase_secrets_get_secret_not_found(self):
        # Mock the return value to simulate no secrets found
        self.mock_phase_instance.get.return_value = []
        
        # Act: Call the function
        phase_secrets_get("NONEXISTENT_KEY", env_name="dev", phase_app="test-app")
        
        # Assert: Verify error message was logged
        # We'll check that the log was called with the right message without asserting exactly once
        self.mock_console_instance.log.assert_any_call("🔍 Secret not found...")
        
        # Verify sys.exit was called with exit code 1
        self.mock_exit.assert_any_call(1)
    
    def test_phase_secrets_get_invalid_format(self):
        # Create a non-dictionary secret to test the error condition
        self.mock_phase_instance.get.return_value = []
        
        # We need to make next() return a non-dictionary value
        # Let's use patch to replace the next() call with a custom function
        with patch('phase_cli.cmd.secrets.get.next', return_value="this is not a dict"):
            # Act: Call the function
            phase_secrets_get("TEST_KEY", env_name="dev", phase_app="test-app")
            
            # Assert: Verify error message was logged with the appropriate error
            self.mock_console_instance.log.assert_any_call("Error: Unexpected format: secret data is not a dictionary")
            
            # Verify sys.exit was called with exit code 1
            self.mock_exit.assert_any_call(1)
    
    def test_phase_secrets_get_api_error(self):
        # Mock Phase.get to raise a ValueError (API error)
        error_message = "API request failed"
        self.mock_phase_instance.get.side_effect = ValueError(error_message)
        
        # Act: Call the function
        phase_secrets_get("TEST_KEY", env_name="dev", phase_app="test-app")
        
        # Assert: Verify error message was logged
        self.mock_console_instance.log.assert_called_once_with(f"Error: {error_message}")
        
        # Verify sys.exit was called with exit code 1
        self.mock_exit.assert_any_call(1)

if __name__ == '__main__':
    unittest.main() 
