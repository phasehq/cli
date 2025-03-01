import unittest
from unittest.mock import patch, MagicMock
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.secret_referencing import resolve_all_secrets

from phase_cli.cmd.run import phase_run_inject

class TestPhaseRunInject(unittest.TestCase):

    @patch('phase_cli.cmd.run.subprocess.run')
    @patch('phase_cli.cmd.run.Console')
    @patch('phase_cli.cmd.run.Progress')
    @patch('phase_cli.cmd.run.resolve_all_secrets')
    @patch('phase_cli.cmd.run.Phase')
    @patch('phase_cli.cmd.run.sys.exit')
    def test_phase_run_inject_success(self, mock_exit, MockPhase, mock_resolve_all_secrets, MockProgress, MockConsole, mock_subprocess_run):
        # Arrange phase: set up mock objects and their return values
        mock_phase_instance = MockPhase.return_value
        mock_console_instance = MockConsole.return_value
        mock_progress_instance = MockProgress.return_value.__enter__.return_value

        # Mock the return value of the get method to simulate fetching secrets
        mock_phase_instance.get.return_value = [
            {'key': 'SECRET_KEY', 'value': 'secret_value', 'environment': 'dev', 'path': '/', 'application': 'app'},
            {'key': 'OTHER_SECRET', 'value': 'other_value', 'environment': 'dev', 'path': '/', 'application': 'app'}
        ]

        # Mock the resolve_all_secrets function to return the secret value as is
        mock_resolve_all_secrets.side_effect = lambda value, all_secrets, phase, app, env: value

        # Mock subprocess.run to return a successful exit code
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_subprocess_run.return_value = mock_process

        command = 'echo "Hello World"'
        env_name = 'dev'
        phase_app = 'app'

        # Act phase: execute the function under test with a clean environment
        with patch.dict('os.environ', {}, clear=True):
            phase_run_inject(command, env_name=env_name, phase_app=phase_app)

        # Assert phase: verify the behavior of the function
        mock_phase_instance.get.assert_called_once_with(env_name=env_name, app_name=phase_app, app_id=None, tag=None, path='/')
        mock_resolve_all_secrets.assert_called()
        mock_subprocess_run.assert_called_once_with(command, shell=True, env=unittest.mock.ANY)
        new_env = mock_subprocess_run.call_args[1]['env']
        self.assertIn('SECRET_KEY', new_env)
        self.assertIn('OTHER_SECRET', new_env)
        self.assertEqual(new_env['SECRET_KEY'], 'secret_value')
        self.assertEqual(new_env['OTHER_SECRET'], 'other_value')
        # Verify that sys.exit was called with the process's return code
        mock_exit.assert_called_once_with(0)
        
    @patch('phase_cli.cmd.run.subprocess.run')
    @patch('phase_cli.cmd.run.Console')
    @patch('phase_cli.cmd.run.Progress')
    @patch('phase_cli.cmd.run.resolve_all_secrets')
    @patch('phase_cli.cmd.run.Phase')
    @patch('phase_cli.cmd.run.sys.exit')
    def test_phase_run_inject_with_different_env(self, mock_exit, MockPhase, mock_resolve_all_secrets, MockProgress, MockConsole, mock_subprocess_run):
        # Arrange phase: set up mock objects and their return values
        mock_phase_instance = MockPhase.return_value
        mock_console_instance = MockConsole.return_value
        mock_progress_instance = MockProgress.return_value.__enter__.return_value

        # Mock the return value of the get method to simulate fetching secrets from a different environment
        mock_phase_instance.get.return_value = [
            {'key': 'SECRET_KEY', 'value': 'secret_value_prod', 'environment': 'prod', 'path': '/', 'application': 'app'},
            {'key': 'OTHER_SECRET', 'value': 'other_value_prod', 'environment': 'prod', 'path': '/', 'application': 'app'}
        ]

        # Mock the resolve_all_secrets function to return the secret value as is
        mock_resolve_all_secrets.side_effect = lambda value, all_secrets, phase, app, env: value

        # Mock subprocess.run to return a successful exit code
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_subprocess_run.return_value = mock_process

        command = 'echo "Hello World"'
        env_name = 'prod'
        phase_app = 'app'

        # Act phase: execute the function under test with a clean environment
        with patch.dict('os.environ', {}, clear=True):
            phase_run_inject(command, env_name=env_name, phase_app=phase_app)

        # Assert phase: verify the behavior of the function
        mock_phase_instance.get.assert_called_once_with(env_name=env_name, app_name=phase_app, app_id=None, tag=None, path='/')
        mock_resolve_all_secrets.assert_called()
        mock_subprocess_run.assert_called_once_with(command, shell=True, env=unittest.mock.ANY)
        new_env = mock_subprocess_run.call_args[1]['env']
        self.assertIn('SECRET_KEY', new_env)
        self.assertIn('OTHER_SECRET', new_env)
        self.assertEqual(new_env['SECRET_KEY'], 'secret_value_prod')
        self.assertEqual(new_env['OTHER_SECRET'], 'other_value_prod')
        # Verify that sys.exit was called with the process's return code
        mock_exit.assert_called_once_with(0)

    @patch('phase_cli.cmd.run.Console')
    @patch('phase_cli.cmd.run.Progress')
    @patch('phase_cli.cmd.run.Phase')
    @patch('phase_cli.cmd.run.sys.exit')
    def test_phase_run_inject_error_handling(self, mock_exit, MockPhase, MockProgress, MockConsole):
        # Arrange phase: set up mock objects and their return values
        mock_phase_instance = MockPhase.return_value
        mock_console_instance = MockConsole.return_value
        mock_progress_instance = MockProgress.return_value.__enter__.return_value

        # Mock the get method to raise a ValueError to simulate an error during secret fetching
        mock_phase_instance.get.side_effect = ValueError("Some error occurred")

        command = 'echo "Hello World"'
        env_name = 'dev'
        phase_app = 'app'

        # Act phase: execute the function under test
        phase_run_inject(command, env_name=env_name, phase_app=phase_app)

        # Verify that the error message was logged and sys.exit was called with 1
        mock_console_instance.log.assert_called_with("Error: Some error occurred")
        mock_phase_instance.get.assert_called_once_with(env_name=env_name, app_name=phase_app, app_id=None, tag=None, path='/')
        mock_exit.assert_called_once_with(1)

    @patch('phase_cli.cmd.run.subprocess.run')
    @patch('phase_cli.cmd.run.Console')
    @patch('phase_cli.cmd.run.Progress')
    @patch('phase_cli.cmd.run.resolve_all_secrets')
    @patch('phase_cli.cmd.run.Phase')
    @patch('phase_cli.cmd.run.sys.exit')
    def test_phase_run_inject_with_app_id(self, mock_exit, MockPhase, mock_resolve_all_secrets, MockProgress, MockConsole, mock_subprocess_run):
        # Arrange phase: set up mock objects and their return values
        mock_phase_instance = MockPhase.return_value
        mock_console_instance = MockConsole.return_value
        mock_progress_instance = MockProgress.return_value.__enter__.return_value

        # Mock the return value of the get method
        mock_phase_instance.get.return_value = [
            {'key': 'SECRET_KEY', 'value': 'secret_value', 'environment': 'dev', 'path': '/', 'application': 'app'}
        ]

        mock_resolve_all_secrets.side_effect = lambda value, all_secrets, phase, app, env: value

        # Mock subprocess.run to return a successful exit code
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_subprocess_run.return_value = mock_process

        command = 'echo "Hello World"'
        env_name = 'dev'
        app_id = 'test-app-id'

        # Act phase: execute the function under test
        with patch.dict('os.environ', {}, clear=True):
            phase_run_inject(command, env_name=env_name, phase_app_id=app_id)

        # Assert phase: verify app_id is used instead of app_name
        mock_phase_instance.get.assert_called_once_with(env_name=env_name, app_name=None, app_id=app_id, tag=None, path='/')
        # Verify that sys.exit was called with the process's return code
        mock_exit.assert_called_once_with(0)

    @patch('phase_cli.cmd.run.subprocess.run')
    @patch('phase_cli.cmd.run.Console')
    @patch('phase_cli.cmd.run.Progress')
    @patch('phase_cli.cmd.run.resolve_all_secrets')
    @patch('phase_cli.cmd.run.Phase')
    @patch('phase_cli.cmd.run.sys.exit')
    def test_phase_run_inject_command_failure(self, mock_exit, MockPhase, mock_resolve_all_secrets, MockProgress, MockConsole, mock_subprocess_run):
        # Arrange phase: set up mock objects and their return values
        mock_phase_instance = MockPhase.return_value
        mock_console_instance = MockConsole.return_value
        mock_progress_instance = MockProgress.return_value.__enter__.return_value

        # Mock the return value of the get method
        mock_phase_instance.get.return_value = [
            {'key': 'SECRET_KEY', 'value': 'secret_value', 'environment': 'dev', 'path': '/', 'application': 'app'}
        ]

        mock_resolve_all_secrets.side_effect = lambda value, all_secrets, phase, app, env: value

        # Mock subprocess.run to return a non-zero exit code to simulate command failure
        mock_process = MagicMock()
        mock_process.returncode = 127  # Command not found error code
        mock_subprocess_run.return_value = mock_process

        command = 'unknown_command'
        env_name = 'dev'
        phase_app = 'app'

        # Act phase: execute the function under test
        with patch.dict('os.environ', {}, clear=True):
            phase_run_inject(command, env_name=env_name, phase_app=phase_app)

        # Assert phase: verify the behavior of the function
        mock_subprocess_run.assert_called_once_with(command, shell=True, env=unittest.mock.ANY)
        # Verify that sys.exit was called with the non-zero return code from the subprocess
        mock_exit.assert_called_once_with(127)
