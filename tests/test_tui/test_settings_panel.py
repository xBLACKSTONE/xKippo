"""
Tests for the settings panel TUI component.
"""

import pytest
from unittest.mock import Mock, patch
from textual.app import App
from textual.widgets import Input, Select, Switch, DataTable, TextArea

from src.honeypot_monitor.tui.settings_panel import (
    SettingsPanel, ConfigurationEditor, IRCConnectionTester, RuleManagementInterface
)
from src.honeypot_monitor.config.config_manager import ConfigManager
from src.honeypot_monitor.config.settings import Settings, IRCSettings


class TestApp(App):
    """Test app for settings panel components."""
    
    def compose(self):
        yield SettingsPanel()


@pytest.fixture
def config_manager():
    """Create a mock config manager."""
    return Mock(spec=ConfigManager)


@pytest.fixture
def sample_settings():
    """Create sample settings for testing."""
    return Settings()


@pytest.fixture
def irc_settings():
    """Create sample IRC settings."""
    return IRCSettings(
        enabled=True,
        server="irc.example.com",
        port=6667,
        channel="#test",
        nickname="test-bot",
        ssl=False,
        alert_types=["new_host", "high_threat"]
    )


class TestConfigurationEditor:
    """Test the configuration editor component."""
    
    def test_initialization(self, config_manager):
        """Test configuration editor initialization."""
        editor = ConfigurationEditor(config_manager)
        assert editor.config_manager == config_manager
        assert editor.current_settings is None
        # For reactive attributes, we need to check the internal value
        assert str(editor.unsaved_changes) == "reactive(False, init=True)"
    
    def test_collect_form_data(self, config_manager):
        """Test collecting data from form fields."""
        editor = ConfigurationEditor(config_manager)
        
        # Mock the query methods
        class MockInput:
            def __init__(self, value=""):
                self.value = value
        
        class MockSelect:
            def __init__(self, value=""):
                self.value = value
        
        class MockSwitch:
            def __init__(self, value=False):
                self.value = value
        
        def mock_query_one(selector, widget_type=None):
            if "honeypot-log-path" in selector:
                return MockInput("/test/path/log.txt")
            elif "honeypot-log-format" in selector:
                return MockSelect("kippo_default")
            elif "monitoring-refresh-interval" in selector:
                return MockInput("2.0")
            elif "monitoring-max-entries" in selector:
                return MockInput("5000")
            elif "analysis-threat-threshold" in selector:
                return MockSelect("high")
            elif "analysis-rules-path" in selector:
                return MockInput("./test-rules/")
            elif "irc-enabled" in selector:
                return MockSwitch(True)
            elif "irc-server" in selector:
                return MockInput("irc.test.com")
            elif "irc-port" in selector:
                return MockInput("6667")
            elif "irc-channel" in selector:
                return MockInput("#test-channel")
            elif "irc-nickname" in selector:
                return MockInput("test-bot")
            elif "irc-ssl" in selector:
                return MockSwitch(False)
            elif "alert-new-host" in selector:
                return MockSwitch(True)
            elif "alert-high-threat" in selector:
                return MockSwitch(True)
            elif "alert-interesting" in selector:
                return MockSwitch(False)
            elif "interface-theme" in selector:
                return MockSelect("dark")
            elif "interface-key-bindings" in selector:
                return MockSelect("vim")
            else:
                return MockInput("")
        
        editor.query_one = mock_query_one
        
        # Collect form data
        settings = editor._collect_form_data()
        
        # Verify settings
        assert settings.honeypot.log_path == "/test/path/log.txt"
        assert settings.honeypot.log_format == "kippo_default"
        assert settings.monitoring.refresh_interval == 2.0
        assert settings.monitoring.max_entries_memory == 5000
        assert settings.analysis.threat_threshold == "high"
        assert settings.analysis.custom_rules_path == "./test-rules/"
        assert settings.irc.enabled == True
        assert settings.irc.server == "irc.test.com"
        assert settings.irc.port == 6667
        assert settings.irc.channel == "#test-channel"
        assert settings.irc.nickname == "test-bot"
        assert settings.irc.ssl == False
        assert "new_host" in settings.irc.alert_types
        assert "high_threat" in settings.irc.alert_types
        assert "interesting_traffic" not in settings.irc.alert_types
        assert settings.interface.theme == "dark"
        assert settings.interface.key_bindings == "vim"
    
    def test_populate_form_fields(self, config_manager, sample_settings):
        """Test populating form fields with settings data."""
        editor = ConfigurationEditor(config_manager)
        editor.current_settings = sample_settings
        
        # Mock the query methods
        class MockWidget:
            def __init__(self):
                self.value = ""
        
        widgets = {}
        
        def mock_query_one(selector, widget_type=None):
            if selector not in widgets:
                widgets[selector] = MockWidget()
            return widgets[selector]
        
        editor.query_one = mock_query_one
        
        # Populate form fields
        editor._populate_form_fields()
        
        # Verify some key fields were populated
        assert widgets["#honeypot-log-path"].value == sample_settings.honeypot.log_path
        assert widgets["#irc-server"].value == sample_settings.irc.server
        assert widgets["#irc-port"].value == str(sample_settings.irc.port)
    
    def test_validation(self, config_manager):
        """Test configuration validation."""
        editor = ConfigurationEditor(config_manager)
        
        # Mock the query methods and status update
        class MockStatic:
            def __init__(self):
                self.content = ""
            
            def update(self, content):
                self.content = content
        
        status_widget = MockStatic()
        
        def mock_query_one(selector, widget_type=None):
            if "validation-status" in selector:
                return status_widget
            # Return mock widgets for form fields
            class MockWidget:
                value = "test"
            return MockWidget()
        
        editor.query_one = mock_query_one
        
        # Mock _collect_form_data to return valid settings
        editor._collect_form_data = lambda: Settings()
        
        # Test validation
        editor._validate_current_config()
        
        # Should show success message
        assert "✅" in status_widget.content


class TestIRCConnectionTester:
    """Test the IRC connection tester component."""
    
    def test_initialization(self):
        """Test IRC connection tester initialization."""
        tester = IRCConnectionTester()
        # For reactive attributes, we need to check the internal value
        assert str(tester.connection_status) == "reactive('Not Connected', init=True)"
        assert str(tester.test_in_progress) == "reactive(False, init=True)"
    
    def test_update_settings(self, irc_settings):
        """Test updating IRC settings display."""
        tester = IRCConnectionTester()
        
        # Mock the query methods
        class MockStatic:
            def __init__(self):
                self.content = ""
            
            def update(self, content):
                self.content = content
        
        widgets = {}
        
        def mock_query_one(selector, widget_type=None):
            if selector not in widgets:
                widgets[selector] = MockStatic()
            return widgets[selector]
        
        tester.query_one = mock_query_one
        
        # Update settings
        tester.update_settings(irc_settings)
        
        # Verify settings were displayed
        assert "irc.example.com" in widgets["#display-server"].content
        assert "6667" in widgets["#display-port"].content
        assert "#test" in widgets["#display-channel"].content
        assert "test-bot" in widgets["#display-nickname"].content
    
    def test_add_log_entry(self):
        """Test adding entries to the connection log."""
        tester = IRCConnectionTester()
        
        # Mock the query method
        class MockStatic:
            def __init__(self):
                self.renderable = "No connection attempts yet"
            
            def update(self, content):
                self.renderable = content
        
        log_widget = MockStatic()
        
        def mock_query_one(selector, widget_type=None):
            return log_widget
        
        tester.query_one = mock_query_one
        
        # Add log entry
        tester._add_log_entry("Test message")
        
        # Verify log entry was added
        assert "Test message" in log_widget.renderable
        assert "[" in log_widget.renderable  # Should contain timestamp


class TestRuleManagementInterface:
    """Test the rule management interface component."""
    
    def test_initialization(self):
        """Test rule management interface initialization."""
        interface = RuleManagementInterface()
        assert interface.rules == []
    
    def test_load_example_rules(self):
        """Test loading example rules."""
        interface = RuleManagementInterface()
        
        # Mock the query methods
        class MockTable:
            def __init__(self):
                self.rows = []
            
            def add_columns(self, *args):
                pass
            
            def add_row(self, *args):
                self.rows.append(args)
        
        table = MockTable()
        
        def mock_query_one(selector, widget_type=None):
            return table
        
        interface.query_one = mock_query_one
        
        # Load example rules
        interface._load_example_rules()
        
        # Verify rules were loaded
        assert len(interface.rules) > 0
        assert len(table.rows) > 0
        assert any(rule['name'] == 'Malware Download' for rule in interface.rules)
    
    def test_populate_rule_form(self):
        """Test populating the rule editor form."""
        interface = RuleManagementInterface()
        
        # Mock the query methods
        class MockWidget:
            def __init__(self):
                self.value = ""
                self.text = ""
        
        widgets = {}
        
        def mock_query_one(selector, widget_type=None):
            if selector not in widgets:
                widgets[selector] = MockWidget()
            return widgets[selector]
        
        interface.query_one = mock_query_one
        
        # Test rule data
        rule = {
            'name': 'Test Rule',
            'type': 'command',
            'pattern': r'test.*pattern',
            'severity': 'high',
            'description': 'Test rule description'
        }
        
        # Populate form
        interface._populate_rule_form(rule)
        
        # Verify form was populated
        assert widgets["#rule-name-input"].value == 'Test Rule'
        assert widgets["#rule-type-select"].value == 'command'
        assert widgets["#rule-pattern-input"].text == r'test.*pattern'
        assert widgets["#rule-severity-select"].value == 'high'
        assert widgets["#rule-description-input"].text == 'Test rule description'
    
    def test_clear_rule_form(self):
        """Test clearing the rule editor form."""
        interface = RuleManagementInterface()
        
        # Mock the query methods
        class MockWidget:
            def __init__(self):
                self.value = "test"
                self.text = "test"
        
        widgets = {}
        
        def mock_query_one(selector, widget_type=None):
            if selector not in widgets:
                widgets[selector] = MockWidget()
            return widgets[selector]
        
        interface.query_one = mock_query_one
        
        # Clear form
        interface._clear_rule_form()
        
        # Verify form was cleared
        assert widgets["#rule-name-input"].value == ""
        assert widgets["#rule-pattern-input"].text == ""
        assert widgets["#rule-description-input"].text == ""


class TestSettingsPanel:
    """Test the main settings panel component."""
    
    def test_initialization(self):
        """Test settings panel initialization."""
        panel = SettingsPanel()
        assert panel.config_manager is not None
    
    def test_get_current_settings(self):
        """Test getting current settings from the panel."""
        panel = SettingsPanel()
        
        # Mock the query method
        class MockConfigEditor:
            def __init__(self):
                self.current_settings = Settings()
        
        def mock_query_one(widget_type):
            return MockConfigEditor()
        
        panel.query_one = mock_query_one
        
        # Get current settings
        settings = panel.get_current_settings()
        
        # Verify settings were returned
        assert settings is not None
        assert isinstance(settings, Settings)
    
    def test_update_irc_tester(self, irc_settings):
        """Test updating the IRC tester with settings."""
        panel = SettingsPanel()
        
        # Mock the query method
        class MockIRCTester:
            def __init__(self):
                self.updated_settings = None
            
            def update_settings(self, settings):
                self.updated_settings = settings
        
        irc_tester = MockIRCTester()
        
        def mock_query_one(widget_type):
            return irc_tester
        
        panel.query_one = mock_query_one
        
        # Update IRC tester
        panel.update_irc_tester(irc_settings)
        
        # Verify settings were passed to tester
        assert irc_tester.updated_settings == irc_settings
    
    def test_get_custom_rules(self):
        """Test getting custom rules from the panel."""
        panel = SettingsPanel()
        
        # Mock the query method
        class MockRuleManager:
            def __init__(self):
                self.rules = [{'name': 'test', 'type': 'command'}]
        
        def mock_query_one(widget_type):
            return MockRuleManager()
        
        panel.query_one = mock_query_one
        
        # Get custom rules
        rules = panel.get_custom_rules()
        
        # Verify rules were returned
        assert len(rules) == 1
        assert rules[0]['name'] == 'test'


# Integration tests would require running the actual Textual app
# These would be more complex and might require special testing frameworks
class TestSettingsPanelIntegration:
    """Integration tests for the settings panel."""
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_full_settings_functionality(self):
        """Test the full settings panel in a Textual app context."""
        # This would test the actual TUI functionality
        # Requires setting up a proper Textual testing environment
        pass
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_configuration_save_load(self):
        """Test saving and loading configuration."""
        # This would test the configuration persistence
        pass
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_irc_connection_testing(self):
        """Test IRC connection testing functionality."""
        # This would test actual IRC connections
        pass
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_rule_management_operations(self):
        """Test rule management CRUD operations."""
        # This would test rule creation, editing, deletion
        pass


if __name__ == "__main__":
    pytest.main([__file__])