import os
import json
import pytest
import tempfile
import shutil
from unittest.mock import patch

from phase_cli.utils.misc import find_phase_config
from phase_cli.utils.const import PHASE_ENV_CONFIG

class TestFindPhaseConfig:
    """Test find_phase_config"""
    
    @pytest.fixture
    def setup_test_dirs(self):
        """Create a temporary directory structure for testing."""
        # Create a temporary base directory
        base_dir = tempfile.mkdtemp()
        
        # Create nested directories
        parent_dir = os.path.join(base_dir, "parent")
        child_dir = os.path.join(parent_dir, "child")
        grandchild_dir = os.path.join(child_dir, "grandchild")
        
        os.makedirs(parent_dir)
        os.makedirs(child_dir)
        os.makedirs(grandchild_dir)
        
        # Return the directory paths and a cleanup function
        yield base_dir, parent_dir, child_dir, grandchild_dir
        
        # Cleanup after test
        shutil.rmtree(base_dir)
    
    def mock_phase_config(self, directory, monorepo_support=False):
        """Helper to create a .phase.json file in a directory."""
        config = {
            "version": "2",
            "phaseApp": "TestApp",
            "appId": "00000000-0000-0000-0000-000000000000",
            "defaultEnv": "Development",
            "envId": "00000000-0000-0000-0000-000000000001",
            "monorepoSupport": monorepo_support
        }
        
        config_path = os.path.join(directory, PHASE_ENV_CONFIG)
        with open(config_path, 'w') as f:
            json.dump(config, f)
        
        return config
    
    def test_find_config_in_current_dir(self, setup_test_dirs):
        """Test finding config in the current directory."""
        _, parent_dir, _, _ = setup_test_dirs
        expected_config = self.mock_phase_config(parent_dir)
        
        with patch('os.getcwd', return_value=parent_dir):
            config = find_phase_config()
            assert config == expected_config
    
    def test_find_config_in_parent_dir_with_monorepo_support(self, setup_test_dirs):
        """Test finding config in a parent directory with monorepoSupport=True."""
        _, parent_dir, _, grandchild_dir = setup_test_dirs
        expected_config = self.mock_phase_config(parent_dir, monorepo_support=True)
        
        with patch('os.getcwd', return_value=grandchild_dir):
            config = find_phase_config()
            assert config == expected_config
    
    def test_find_config_in_parent_dir_without_monorepo_support(self, setup_test_dirs):
        """Test finding config in a parent directory with monorepoSupport=False."""
        _, parent_dir, _, grandchild_dir = setup_test_dirs
        self.mock_phase_config(parent_dir, monorepo_support=False)
        
        with patch('os.getcwd', return_value=grandchild_dir):
            config = find_phase_config()
            assert config is None
    
    def test_max_depth_parameter(self, setup_test_dirs):
        """Test respecting the max_depth parameter."""
        _, parent_dir, child_dir, grandchild_dir = setup_test_dirs
        expected_config = self.mock_phase_config(parent_dir, monorepo_support=True)
        
        # Test with max_depth=1 (should not find config in parent)
        with patch('os.getcwd', return_value=grandchild_dir):
            config = find_phase_config(max_depth=1)
            assert config is None
        
        # Test with max_depth=2 (should find config in parent)
        with patch('os.getcwd', return_value=grandchild_dir):
            config = find_phase_config(max_depth=2)
            assert config == expected_config
    
    def test_env_variable_override(self, setup_test_dirs):
        """Test respecting the PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH environment variable."""
        _, parent_dir, child_dir, grandchild_dir = setup_test_dirs
        expected_config = self.mock_phase_config(parent_dir, monorepo_support=True)
        
        # Test with environment variable set to 1 (should not find config in parent)
        with patch('os.getcwd', return_value=grandchild_dir), \
             patch.dict('os.environ', {'PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH': '1'}):
            config = find_phase_config()
            assert config is None
        
        # Test with environment variable set to 2 (should find config in parent)
        with patch('os.getcwd', return_value=grandchild_dir), \
             patch.dict('os.environ', {'PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH': '2'}):
            config = find_phase_config()
            assert config == expected_config
    
    def test_no_config_found(self, setup_test_dirs):
        """Test that None is returned when no config is found."""
        base_dir, _, _, _ = setup_test_dirs
        
        with patch('os.getcwd', return_value=base_dir):
            config = find_phase_config()
            assert config is None
            
    def test_invalid_json_config(self, setup_test_dirs):
        """Test handling of invalid JSON in config file."""
        _, parent_dir, _, _ = setup_test_dirs
        
        # Create an invalid JSON file
        config_path = os.path.join(parent_dir, PHASE_ENV_CONFIG)
        with open(config_path, 'w') as f:
            f.write("{invalid json}")
        
        with patch('os.getcwd', return_value=parent_dir):
            config = find_phase_config()
            assert config is None
    
    def test_file_not_found_error(self):
        """Test handling of FileNotFoundError when trying to open config."""
        mock_path_exists = patch('os.path.exists', return_value=True)
        mock_file_open = patch('builtins.open', side_effect=FileNotFoundError)
        
        with patch('os.getcwd', return_value='/fake/path'), mock_path_exists, mock_file_open:
            config = find_phase_config()
            assert config is None
    
    def test_os_error(self):
        """Test handling of OSError when trying to open config."""
        mock_path_exists = patch('os.path.exists', return_value=True)
        mock_file_open = patch('builtins.open', side_effect=OSError)
        
        with patch('os.getcwd', return_value='/fake/path'), mock_path_exists, mock_file_open:
            config = find_phase_config()
            assert config is None
            
    def test_reach_root_directory(self):
        """Test that the function stops when reaching the root directory."""
        # Define a custom side effect function for os.path.dirname
        def dirname_side_effect(path):
            if path == '/fakepath/path':
                return '/fakepath'
            elif path == '/fakepath':
                return '/'
            else:
                return '/'  # Keep returning root for any additional calls
        
        # Mock the directory structure to simulate reaching root
        with patch('os.getcwd', return_value='/fakepath/path'), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.dirname', side_effect=dirname_side_effect), \
             patch('os.path.samefile', return_value=False):
            config = find_phase_config(max_depth=10)
            assert config is None 
