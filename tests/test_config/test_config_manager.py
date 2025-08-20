"""
Unit tests for ConfigManager class.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open

from src.honeypot_monitor.config.config_manager import ConfigManager, ConfigValidationError
from src.honeypot_monitor.config.settings import (
    Settings, HoneypotSettings, MonitoringSettings, 
    AnalysisSettings, IRCSettings, InterfaceSettings
)


class TestConfigManager:
    """Test cases for ConfigManager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config_manager = ConfigManager()
    
    def test_load_default_config(self):
        """Test loading default configuration."""
        settings = self.config_manager.load_config()
        
        assert isinstance(settings, Settings)
        assert isinstance(settings.honeypot, HoneypotSettings)
        assert isinstance(settings.monitoring, MonitoringSettings)
        assert isinstance(settings.analysis, AnalysisSettings)
        assert isinstance(settings.irc, IRCSettings)
        assert isinstance(settings.interface, InterfaceSettings)
    
    def test_load_valid_config_file(self):
        """Test loading a valid configuration file."""
        valid_config = """
honeypot:
  log_path: "/custom/path/kippo.log"
  log_format: "cowrie"

monitoring:
  refresh_interval: 2.5
  max_entries_memory: 5000

analysis:
  threat_threshold: "high"
  custom_rules_path: "/custom/rules/"

irc:
  enabled: false
  server: "irc.example.com"
  port: 6697
  channel: "#test"
  nickname: "test-bot"
  ssl: true
  alert_types:
    - "new_host"
    - "high_threat"

interface:
  theme: "light"
  key_bindings: "vim"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(valid_config)
            temp_path = f.name
        
        try:
            settings = self.config_manager.load_config(temp_path)
            
            # Verify honeypot settings
            assert settings.honeypot.log_path == "/custom/path/kippo.log"
            assert settings.honeypot.log_format == "cowrie"
            
            # Verify monitoring settings
            assert settings.monitoring.refresh_interval == 2.5
            assert settings.monitoring.max_entries_memory == 5000
            
            # Verify analysis settings
            assert settings.analysis.threat_threshold == "high"
            assert settings.analysis.custom_rules_path == "/custom/rules/"
            
            # Verify IRC settings
            assert settings.irc.enabled is False
            assert settings.irc.server == "irc.example.com"
            assert settings.irc.port == 6697
            assert settings.irc.channel == "#test"
            assert settings.irc.nickname == "test-bot"
            assert settings.irc.ssl is True
            assert settings.irc.alert_types == ["new_host", "high_threat"]
            
            # Verify interface settings
            assert settings.interface.theme == "light"
            assert settings.interface.key_bindings == "vim"
            
        finally:
            os.unlink(temp_path)
    
    def test_load_partial_config_uses_defaults(self):
        """Test that partial configuration uses default values."""
        partial_config = """
honeypot:
  log_path: "/custom/path/kippo.log"

irc:
  enabled: false
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(partial_config)
            temp_path = f.name
        
        try:
            settings = self.config_manager.load_config(temp_path)
            
            # Custom values
            assert settings.honeypot.log_path == "/custom/path/kippo.log"
            assert settings.irc.enabled is False
            
            # Default values
            assert settings.honeypot.log_format == "kippo_default"
            assert settings.monitoring.refresh_interval == 1.0
            assert settings.analysis.threat_threshold == "medium"
            assert settings.irc.server == "irc.freenode.net"
            assert settings.interface.theme == "dark"
            
        finally:
            os.unlink(temp_path)
    
    def test_load_nonexistent_file_raises_error(self):
        """Test that loading nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            self.config_manager.load_config("/nonexistent/path/config.yaml")
    
    def test_load_invalid_yaml_raises_error(self):
        """Test that invalid YAML raises ConfigValidationError."""
        invalid_yaml = """
honeypot:
  log_path: "/path/to/log"
  invalid_yaml: [unclosed list
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="Invalid YAML"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_honeypot_settings_invalid_log_format(self):
        """Test validation of invalid honeypot log format."""
        invalid_config = """
honeypot:
  log_format: "invalid_format"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="honeypot.log_format must be one of"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_monitoring_settings_invalid_refresh_interval(self):
        """Test validation of invalid monitoring refresh interval."""
        invalid_config = """
monitoring:
  refresh_interval: -1.0
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="monitoring.refresh_interval must be positive"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_monitoring_settings_invalid_max_entries(self):
        """Test validation of invalid max entries memory."""
        invalid_config = """
monitoring:
  max_entries_memory: "not_a_number"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="monitoring.max_entries_memory must be an integer"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_analysis_settings_invalid_threat_threshold(self):
        """Test validation of invalid analysis threat threshold."""
        invalid_config = """
analysis:
  threat_threshold: "invalid_threshold"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="analysis.threat_threshold must be one of"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_irc_settings_invalid_port(self):
        """Test validation of invalid IRC port."""
        invalid_config = """
irc:
  port: 70000
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="irc.port must be between 1 and 65535"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_irc_settings_empty_server(self):
        """Test validation of empty IRC server."""
        invalid_config = """
irc:
  server: ""
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="irc.server cannot be empty"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_irc_settings_invalid_alert_types(self):
        """Test validation of invalid IRC alert types."""
        invalid_config = """
irc:
  alert_types:
    - "new_host"
    - "invalid_alert_type"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="Invalid alert type 'invalid_alert_type'"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_interface_settings_invalid_theme(self):
        """Test validation of invalid interface theme."""
        invalid_config = """
interface:
  theme: "invalid_theme"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="interface.theme must be one of"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_interface_settings_invalid_key_bindings(self):
        """Test validation of invalid interface key bindings."""
        invalid_config = """
interface:
  key_bindings: "invalid_bindings"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="interface.key_bindings must be one of"):
                self.config_manager.load_config(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_config_file_method(self):
        """Test the validate_config_file method."""
        valid_config = """
honeypot:
  log_path: "/test/path"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(valid_config)
            temp_path = f.name
        
        try:
            # Valid config should return True
            assert self.config_manager.validate_config_file(temp_path) is True
        finally:
            os.unlink(temp_path)
        
        # Invalid config should raise exception
        invalid_config = """
honeypot:
  log_format: "invalid_format"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_config)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError):
                self.config_manager.validate_config_file(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_empty_config_file_uses_defaults(self):
        """Test that empty config file uses all default values."""
        empty_config = ""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(empty_config)
            temp_path = f.name
        
        try:
            settings = self.config_manager.load_config(temp_path)
            
            # All should be default values
            assert settings.honeypot.log_path == "/opt/kippo/log/kippo.log"
            assert settings.honeypot.log_format == "kippo_default"
            assert settings.monitoring.refresh_interval == 1.0
            assert settings.monitoring.max_entries_memory == 10000
            assert settings.analysis.threat_threshold == "medium"
            assert settings.analysis.custom_rules_path == "./rules/"
            assert settings.irc.enabled is True
            assert settings.irc.server == "irc.freenode.net"
            assert settings.irc.port == 6667
            assert settings.irc.channel == "#security-alerts"
            assert settings.irc.nickname == "honeypot-monitor"
            assert settings.irc.ssl is False
            assert settings.irc.alert_types == ["new_host", "high_threat", "interesting_traffic"]
            assert settings.interface.theme == "dark"
            assert settings.interface.key_bindings == "default"
            
        finally:
            os.unlink(temp_path)


class TestConfigGeneration:
    """Test cases for configuration generation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config_manager = ConfigManager()
    
    def test_detect_honeypot_paths_no_files(self):
        """Test honeypot path detection when no files exist."""
        # Mock glob to return empty results
        with patch('src.honeypot_monitor.config.config_manager.glob.glob', return_value=[]):
            paths = self.config_manager.detect_honeypot_paths()
            assert paths == []
    
    def test_detect_honeypot_paths_with_files(self):
        """Test honeypot path detection with existing files."""
        mock_paths = ['/opt/kippo/log/kippo.log', '/opt/cowrie/var/log/cowrie/cowrie.log']
        
        with patch('src.honeypot_monitor.config.config_manager.glob.glob') as mock_glob:
            with patch('pathlib.Path.exists', return_value=True):
                with patch('pathlib.Path.is_file', return_value=True):
                    with patch('pathlib.Path.stat') as mock_stat:
                        # Mock file size > 0
                        mock_stat.return_value.st_size = 1024
                        
                        # Mock glob to return our test paths for specific patterns
                        def glob_side_effect(pattern, recursive=False):
                            if '/opt/kippo/log/kippo.log' in pattern:
                                return ['/opt/kippo/log/kippo.log']
                            elif '/opt/cowrie/var/log/cowrie/cowrie.log' in pattern:
                                return ['/opt/cowrie/var/log/cowrie/cowrie.log']
                            return []
                        
                        mock_glob.side_effect = glob_side_effect
                        
                        paths = self.config_manager.detect_honeypot_paths()
                        assert '/opt/kippo/log/kippo.log' in paths
                        assert '/opt/cowrie/var/log/cowrie/cowrie.log' in paths
    
    def test_generate_config_file(self):
        """Test generating configuration file from Settings object."""
        settings = Settings(
            honeypot=HoneypotSettings(log_path="/test/path", log_format="cowrie"),
            monitoring=MonitoringSettings(refresh_interval=2.0, max_entries_memory=5000),
            analysis=AnalysisSettings(threat_threshold="high", custom_rules_path="/test/rules/"),
            irc=IRCSettings(
                enabled=False,
                server="test.server.com",
                port=6697,
                channel="#test",
                nickname="test-bot",
                ssl=True,
                alert_types=["new_host"]
            ),
            interface=InterfaceSettings(theme="light", key_bindings="vim")
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            self.config_manager.generate_config_file(temp_path, settings)
            
            # Verify file was created and contains expected content
            assert Path(temp_path).exists()
            
            with open(temp_path, 'r') as f:
                content = f.read()
                assert 'log_path: /test/path' in content
                assert 'log_format: cowrie' in content
                assert 'refresh_interval: 2.0' in content
                assert 'max_entries_memory: 5000' in content
                assert 'threat_threshold: high' in content
                assert 'enabled: false' in content
                assert 'server: test.server.com' in content
                assert 'port: 6697' in content
                assert 'theme: light' in content
                assert 'key_bindings: vim' in content
                
        finally:
            os.unlink(temp_path)
    
    def test_generate_config_file_creates_directory(self):
        """Test that generate_config_file creates parent directories."""
        settings = Settings()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "subdir" / "config.yaml"
            
            self.config_manager.generate_config_file(str(config_path), settings)
            
            assert config_path.exists()
            assert config_path.parent.exists()
    
    def test_create_default_config(self):
        """Test creating default configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            settings = self.config_manager.create_default_config(temp_path)
            
            # Verify settings object
            assert isinstance(settings, Settings)
            assert settings.honeypot.log_path == "/opt/kippo/log/kippo.log"
            assert settings.honeypot.log_format == "kippo_default"
            
            # Verify file was created
            assert Path(temp_path).exists()
            
        finally:
            os.unlink(temp_path)
    
    def test_create_default_config_with_custom_path(self):
        """Test creating default configuration with custom honeypot path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            custom_log_path = "/custom/cowrie/log/cowrie.log"
            settings = self.config_manager.create_default_config(temp_path, custom_log_path)
            
            # Verify custom path is used
            assert settings.honeypot.log_path == custom_log_path
            # Verify format is auto-detected
            assert settings.honeypot.log_format == "cowrie"
            
        finally:
            os.unlink(temp_path)
    
    def test_create_default_config_kippo_detection(self):
        """Test that Kippo format is detected from path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            custom_log_path = "/opt/kippo/log/kippo.log"
            settings = self.config_manager.create_default_config(temp_path, custom_log_path)
            
            assert settings.honeypot.log_path == custom_log_path
            assert settings.honeypot.log_format == "kippo_default"
            
        finally:
            os.unlink(temp_path)
    
    def test_interactive_config_setup_mock(self):
        """Test interactive configuration setup with mocked input."""
        # Mock user inputs
        mock_inputs = [
            "1",  # Select first detected path
            "",   # Use default log format
            "",   # Use default refresh interval
            "",   # Use default max entries
            "",   # Use default threat threshold
            "n",  # Disable IRC
            "",   # Use default theme
            ""    # Use default key bindings
        ]
        
        detected_paths = ["/opt/kippo/log/kippo.log"]
        
        with patch('src.honeypot_monitor.config.config_manager.ConfigManager.detect_honeypot_paths', return_value=detected_paths):
            with patch('builtins.input', side_effect=mock_inputs):
                with patch('builtins.print'):  # Suppress print output during test
                    settings = self.config_manager.interactive_config_setup()
                    
                    assert isinstance(settings, Settings)
                    assert settings.honeypot.log_path == "/opt/kippo/log/kippo.log"
                    assert settings.honeypot.log_format == "kippo_default"
                    assert settings.monitoring.refresh_interval == 1.0
                    assert settings.monitoring.max_entries_memory == 10000
                    assert settings.analysis.threat_threshold == "medium"
                    assert settings.irc.enabled is False
                    assert settings.interface.theme == "dark"
                    assert settings.interface.key_bindings == "default"
    
    def test_interactive_config_setup_custom_values(self):
        """Test interactive configuration setup with custom values."""
        mock_inputs = [
            "2",                    # Enter custom path
            "/custom/log/path.log", # Custom log path
            "cowrie",              # Custom log format
            "2.5",                 # Custom refresh interval
            "5000",                # Custom max entries
            "high",                # Custom threat threshold
            "y",                   # Enable IRC
            "irc.example.com",     # Custom IRC server
            "6697",                # Custom IRC port
            "#custom",             # Custom IRC channel
            "custom-bot",          # Custom IRC nickname
            "y",                   # Enable SSL
            "light",               # Custom theme
            "vim"                  # Custom key bindings
        ]
        
        detected_paths = ["/opt/kippo/log/kippo.log"]
        
        with patch('src.honeypot_monitor.config.config_manager.ConfigManager.detect_honeypot_paths', return_value=detected_paths):
            with patch('builtins.input', side_effect=mock_inputs):
                with patch('builtins.print'):
                    with patch('pathlib.Path.exists', return_value=True):  # Mock custom path exists
                        settings = self.config_manager.interactive_config_setup()
                        
                        assert settings.honeypot.log_path == "/custom/log/path.log"
                        assert settings.honeypot.log_format == "cowrie"
                        assert settings.monitoring.refresh_interval == 2.5
                        assert settings.monitoring.max_entries_memory == 5000
                        assert settings.analysis.threat_threshold == "high"
                        assert settings.irc.enabled is True
                        assert settings.irc.server == "irc.example.com"
                        assert settings.irc.port == 6697
                        assert settings.irc.channel == "#custom"
                        assert settings.irc.nickname == "custom-bot"
                        assert settings.irc.ssl is True
                        assert settings.interface.theme == "light"
                        assert settings.interface.key_bindings == "vim"
    
    def test_interactive_config_setup_no_detected_paths(self):
        """Test interactive setup when no honeypot paths are detected."""
        mock_inputs = [
            "/manual/path/log.log",  # Manual log path entry
            "",                      # Use default log format
            "",                      # Use default refresh interval
            "",                      # Use default max entries
            "",                      # Use default threat threshold
            "n",                     # Disable IRC
            "",                      # Use default theme
            ""                       # Use default key bindings
        ]
        
        with patch('src.honeypot_monitor.config.config_manager.ConfigManager.detect_honeypot_paths', return_value=[]):
            with patch('builtins.input', side_effect=mock_inputs):
                with patch('builtins.print'):
                    settings = self.config_manager.interactive_config_setup()
                    
                    assert settings.honeypot.log_path == "/manual/path/log.log"
                    assert settings.honeypot.log_format == "kippo_default"