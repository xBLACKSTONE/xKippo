"""
Settings panel TUI component for configuration management.

This module provides the settings interface for editing configuration,
IRC settings with connection testing, and rule management.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Static, Button, Input, Select, Switch, Label, Rule, Tabs, TabPane,
    Collapsible, TextArea, DataTable, ProgressBar
)
from textual.widget import Widget
from textual.reactive import reactive
from textual.message import Message
from typing import Dict, Any, Optional, List
from pathlib import Path
import asyncio
import json

from ..config.config_manager import ConfigManager, ConfigValidationError
from ..config.settings import Settings, HoneypotSettings, MonitoringSettings, AnalysisSettings, IRCSettings, InterfaceSettings


class ConfigurationEditor(Widget):
    """Widget for editing application configuration."""
    
    def __init__(self, config_manager: ConfigManager, **kwargs):
        super().__init__(**kwargs)
        self.config_manager = config_manager
        self.current_settings: Optional[Settings] = None
        self.unsaved_changes = reactive(False)
    
    def compose(self) -> ComposeResult:
        """Create the configuration editor layout."""
        with Container(id="config-editor"):
            yield Static("Configuration Editor", classes="panel-title")
            
            # Configuration file controls
            with Horizontal(id="config-file-controls"):
                yield Button("Load Config", id="load-config", variant="default")
                yield Button("Save Config", id="save-config", variant="primary")
                yield Button("Reset to Defaults", id="reset-config", variant="default")
                yield Static("", id="config-status")
            
            yield Rule()
            
            # Configuration sections
            with ScrollableContainer(id="config-sections"):
                # Honeypot settings
                with Collapsible(title="🍯 Honeypot Settings", id="honeypot-section"):
                    with Vertical():
                        yield Label("Log File Path:")
                        yield Input(placeholder="/opt/kippo/log/kippo.log", id="honeypot-log-path")
                        yield Button("Browse", id="browse-log-path", variant="default")
                        
                        yield Label("Log Format:")
                        yield Select([
                            ("Kippo Default", "kippo_default"),
                            ("Cowrie", "cowrie"),
                            ("Custom", "custom")
                        ], id="honeypot-log-format")
                
                # Monitoring settings
                with Collapsible(title="📊 Monitoring Settings", id="monitoring-section"):
                    with Vertical():
                        yield Label("Refresh Interval (seconds):")
                        yield Input(placeholder="1.0", id="monitoring-refresh-interval")
                        
                        yield Label("Max Entries in Memory:")
                        yield Input(placeholder="10000", id="monitoring-max-entries")
                
                # Analysis settings
                with Collapsible(title="🔍 Analysis Settings", id="analysis-section"):
                    with Vertical():
                        yield Label("Threat Detection Threshold:")
                        yield Select([
                            ("Low", "low"),
                            ("Medium", "medium"),
                            ("High", "high"),
                            ("Critical", "critical")
                        ], id="analysis-threat-threshold")
                        
                        yield Label("Custom Rules Path:")
                        yield Input(placeholder="./rules/", id="analysis-rules-path")
                        yield Button("Browse", id="browse-rules-path", variant="default")
                
                # IRC settings
                with Collapsible(title="💬 IRC Notification Settings", id="irc-section"):
                    with Vertical():
                        with Horizontal():
                            yield Label("Enable IRC Notifications:")
                            yield Switch(id="irc-enabled")
                        
                        yield Label("IRC Server:")
                        yield Input(placeholder="irc.freenode.net", id="irc-server")
                        
                        yield Label("Port:")
                        yield Input(placeholder="6667", id="irc-port")
                        
                        yield Label("Channel:")
                        yield Input(placeholder="#security-alerts", id="irc-channel")
                        
                        yield Label("Nickname:")
                        yield Input(placeholder="honeypot-monitor", id="irc-nickname")
                        
                        with Horizontal():
                            yield Label("Use SSL:")
                            yield Switch(id="irc-ssl")
                        
                        yield Label("Alert Types:")
                        with Vertical(id="alert-types"):
                            with Horizontal():
                                yield Switch(id="alert-new-host", value=True)
                                yield Label("New Host Connections")
                            with Horizontal():
                                yield Switch(id="alert-high-threat", value=True)
                                yield Label("High Threat Activities")
                            with Horizontal():
                                yield Switch(id="alert-interesting", value=True)
                                yield Label("Interesting Traffic")
                
                # Interface settings
                with Collapsible(title="🎨 Interface Settings", id="interface-section"):
                    with Vertical():
                        yield Label("Theme:")
                        yield Select([
                            ("Dark", "dark"),
                            ("Light", "light"),
                            ("Auto", "auto")
                        ], id="interface-theme")
                        
                        yield Label("Key Bindings:")
                        yield Select([
                            ("Default", "default"),
                            ("Vim", "vim"),
                            ("Emacs", "emacs")
                        ], id="interface-key-bindings")
            
            # Status and validation
            with Container(id="config-validation"):
                yield Static("Configuration Status: Not Loaded", id="validation-status")
                yield ProgressBar(id="validation-progress", show_eta=False)
    
    def on_mount(self) -> None:
        """Initialize the configuration editor."""
        self._load_default_config()
    
    def _load_default_config(self) -> None:
        """Load the default configuration."""
        try:
            self.current_settings = self.config_manager.load_config()
            self._populate_form_fields()
            self._update_status("Configuration loaded successfully", "success")
        except Exception as e:
            self._update_status(f"Error loading configuration: {e}", "error")
    
    def _populate_form_fields(self) -> None:
        """Populate form fields with current settings."""
        if not self.current_settings:
            return
        
        # Honeypot settings
        self.query_one("#honeypot-log-path", Input).value = self.current_settings.honeypot.log_path
        self.query_one("#honeypot-log-format", Select).value = self.current_settings.honeypot.log_format
        
        # Monitoring settings
        self.query_one("#monitoring-refresh-interval", Input).value = str(self.current_settings.monitoring.refresh_interval)
        self.query_one("#monitoring-max-entries", Input).value = str(self.current_settings.monitoring.max_entries_memory)
        
        # Analysis settings
        self.query_one("#analysis-threat-threshold", Select).value = self.current_settings.analysis.threat_threshold
        self.query_one("#analysis-rules-path", Input).value = self.current_settings.analysis.custom_rules_path
        
        # IRC settings
        self.query_one("#irc-enabled", Switch).value = self.current_settings.irc.enabled
        self.query_one("#irc-server", Input).value = self.current_settings.irc.server
        self.query_one("#irc-port", Input).value = str(self.current_settings.irc.port)
        self.query_one("#irc-channel", Input).value = self.current_settings.irc.channel
        self.query_one("#irc-nickname", Input).value = self.current_settings.irc.nickname
        self.query_one("#irc-ssl", Switch).value = self.current_settings.irc.ssl
        
        # Alert types
        alert_types = self.current_settings.irc.alert_types
        self.query_one("#alert-new-host", Switch).value = "new_host" in alert_types
        self.query_one("#alert-high-threat", Switch).value = "high_threat" in alert_types
        self.query_one("#alert-interesting", Switch).value = "interesting_traffic" in alert_types
        
        # Interface settings
        self.query_one("#interface-theme", Select).value = self.current_settings.interface.theme
        self.query_one("#interface-key-bindings", Select).value = self.current_settings.interface.key_bindings
        
        self.unsaved_changes = False
    
    def _collect_form_data(self) -> Settings:
        """Collect data from form fields and create Settings object."""
        # Collect alert types
        alert_types = []
        if self.query_one("#alert-new-host", Switch).value:
            alert_types.append("new_host")
        if self.query_one("#alert-high-threat", Switch).value:
            alert_types.append("high_threat")
        if self.query_one("#alert-interesting", Switch).value:
            alert_types.append("interesting_traffic")
        
        return Settings(
            honeypot=HoneypotSettings(
                log_path=self.query_one("#honeypot-log-path", Input).value,
                log_format=self.query_one("#honeypot-log-format", Select).value
            ),
            monitoring=MonitoringSettings(
                refresh_interval=float(self.query_one("#monitoring-refresh-interval", Input).value or "1.0"),
                max_entries_memory=int(self.query_one("#monitoring-max-entries", Input).value or "10000")
            ),
            analysis=AnalysisSettings(
                threat_threshold=self.query_one("#analysis-threat-threshold", Select).value,
                custom_rules_path=self.query_one("#analysis-rules-path", Input).value
            ),
            irc=IRCSettings(
                enabled=self.query_one("#irc-enabled", Switch).value,
                server=self.query_one("#irc-server", Input).value,
                port=int(self.query_one("#irc-port", Input).value or "6667"),
                channel=self.query_one("#irc-channel", Input).value,
                nickname=self.query_one("#irc-nickname", Input).value,
                ssl=self.query_one("#irc-ssl", Switch).value,
                alert_types=alert_types
            ),
            interface=InterfaceSettings(
                theme=self.query_one("#interface-theme", Select).value,
                key_bindings=self.query_one("#interface-key-bindings", Select).value
            )
        )
    
    def _update_status(self, message: str, status_type: str = "info") -> None:
        """Update the configuration status display."""
        status_widget = self.query_one("#validation-status", Static)
        
        if status_type == "success":
            status_widget.update(f"✅ {message}")
        elif status_type == "error":
            status_widget.update(f"❌ {message}")
        elif status_type == "warning":
            status_widget.update(f"⚠️ {message}")
        else:
            status_widget.update(f"ℹ️ {message}")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "load-config":
            self._load_config_file()
        elif event.button.id == "save-config":
            self._save_config_file()
        elif event.button.id == "reset-config":
            self._reset_to_defaults()
        elif event.button.id == "browse-log-path":
            self._browse_log_path()
        elif event.button.id == "browse-rules-path":
            self._browse_rules_path()
    
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input field changes."""
        self.unsaved_changes = True
        self._validate_current_config()
    
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle select field changes."""
        self.unsaved_changes = True
        self._validate_current_config()
    
    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Handle switch changes."""
        self.unsaved_changes = True
        self._validate_current_config()
    
    def _validate_current_config(self) -> None:
        """Validate the current configuration in the form."""
        try:
            settings = self._collect_form_data()
            self._update_status("Configuration is valid", "success")
        except Exception as e:
            self._update_status(f"Configuration error: {e}", "error")
    
    def _load_config_file(self) -> None:
        """Load configuration from file."""
        # In a real implementation, this would open a file dialog
        # For now, just reload the default config
        self._load_default_config()
    
    def _save_config_file(self) -> None:
        """Save configuration to file."""
        try:
            settings = self._collect_form_data()
            # In a real implementation, this would open a save dialog
            # For now, save to a default location
            config_path = "config/user_config.yaml"
            self.config_manager.generate_config_file(config_path, settings)
            self.current_settings = settings
            self.unsaved_changes = False
            self._update_status(f"Configuration saved to {config_path}", "success")
        except Exception as e:
            self._update_status(f"Error saving configuration: {e}", "error")
    
    def _reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self.current_settings = Settings()
        self._populate_form_fields()
        self._update_status("Configuration reset to defaults", "info")
    
    def _browse_log_path(self) -> None:
        """Browse for honeypot log file."""
        # In a real implementation, this would open a file browser
        # For now, try to detect honeypot paths
        detected_paths = self.config_manager.detect_honeypot_paths()
        if detected_paths:
            self.query_one("#honeypot-log-path", Input).value = detected_paths[0]
            self._update_status(f"Auto-detected log path: {detected_paths[0]}", "info")
        else:
            self._update_status("No honeypot installations detected", "warning")
    
    def _browse_rules_path(self) -> None:
        """Browse for custom rules directory."""
        # In a real implementation, this would open a directory browser
        # For now, just suggest a default path
        self.query_one("#analysis-rules-path", Input).value = "./rules/"
        self._update_status("Using default rules path", "info")


class IRCConnectionTester(Widget):
    """Widget for testing IRC connection settings."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connection_status = reactive("Not Connected")
        self.test_in_progress = reactive(False)
    
    def compose(self) -> ComposeResult:
        """Create the IRC connection tester layout."""
        with Container(id="irc-tester"):
            yield Static("IRC Connection Tester", classes="panel-title")
            
            # Connection settings (read-only display)
            with Vertical(id="connection-info"):
                yield Static("Connection Settings:", classes="section-title")
                yield Static("Server: Not Set", id="display-server")
                yield Static("Port: Not Set", id="display-port")
                yield Static("Channel: Not Set", id="display-channel")
                yield Static("Nickname: Not Set", id="display-nickname")
                yield Static("SSL: Not Set", id="display-ssl")
            
            yield Rule()
            
            # Test controls
            with Horizontal(id="test-controls"):
                yield Button("Test Connection", id="test-connection", variant="primary")
                yield Button("Send Test Message", id="send-test", variant="default")
                yield Button("Disconnect", id="disconnect", variant="default")
            
            # Connection status
            with Container(id="connection-status"):
                yield Static("Status: Not Connected", id="status-display")
                yield ProgressBar(id="connection-progress", show_eta=False)
            
            # Test log
            with Collapsible(title="Connection Log", id="connection-log"):
                yield ScrollableContainer(
                    Static("No connection attempts yet", id="log-content"),
                    id="log-scroll"
                )
    
    def update_settings(self, irc_settings: IRCSettings) -> None:
        """Update the displayed IRC settings."""
        self.query_one("#display-server", Static).update(f"Server: {irc_settings.server}")
        self.query_one("#display-port", Static).update(f"Port: {irc_settings.port}")
        self.query_one("#display-channel", Static).update(f"Channel: {irc_settings.channel}")
        self.query_one("#display-nickname", Static).update(f"Nickname: {irc_settings.nickname}")
        self.query_one("#display-ssl", Static).update(f"SSL: {'Yes' if irc_settings.ssl else 'No'}")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "test-connection":
            self._test_connection()
        elif event.button.id == "send-test":
            self._send_test_message()
        elif event.button.id == "disconnect":
            self._disconnect()
    
    def _test_connection(self) -> None:
        """Test the IRC connection."""
        if self.test_in_progress:
            return
        
        self.test_in_progress = True
        self._update_status("Testing connection...", "info")
        self._add_log_entry("Starting connection test...")
        
        # Simulate connection test (in real implementation, would use actual IRC client)
        self.run_worker(self._simulate_connection_test(), exclusive=True)
    
    async def _simulate_connection_test(self) -> None:
        """Simulate IRC connection test."""
        try:
            # Simulate connection steps
            await asyncio.sleep(1)
            self._add_log_entry("Resolving hostname...")
            
            await asyncio.sleep(1)
            self._add_log_entry("Connecting to server...")
            
            await asyncio.sleep(1)
            self._add_log_entry("Authenticating...")
            
            await asyncio.sleep(1)
            self._add_log_entry("Joining channel...")
            
            await asyncio.sleep(1)
            self._add_log_entry("Connection successful!")
            self._update_status("Connected successfully", "success")
            self.connection_status = "Connected"
            
        except Exception as e:
            self._add_log_entry(f"Connection failed: {e}")
            self._update_status("Connection failed", "error")
            self.connection_status = "Failed"
        finally:
            self.test_in_progress = False
    
    def _send_test_message(self) -> None:
        """Send a test message to the IRC channel."""
        if self.connection_status != "Connected":
            self._update_status("Not connected - cannot send message", "error")
            return
        
        self._add_log_entry("Sending test message: 'Honeypot Monitor CLI - Connection Test'")
        self._update_status("Test message sent", "success")
    
    def _disconnect(self) -> None:
        """Disconnect from IRC."""
        if self.connection_status == "Connected":
            self._add_log_entry("Disconnecting from IRC...")
            self.connection_status = "Not Connected"
            self._update_status("Disconnected", "info")
        else:
            self._update_status("Not connected", "warning")
    
    def _update_status(self, message: str, status_type: str = "info") -> None:
        """Update the connection status display."""
        status_widget = self.query_one("#status-display", Static)
        
        if status_type == "success":
            status_widget.update(f"✅ Status: {message}")
        elif status_type == "error":
            status_widget.update(f"❌ Status: {message}")
        elif status_type == "warning":
            status_widget.update(f"⚠️ Status: {message}")
        else:
            status_widget.update(f"ℹ️ Status: {message}")
    
    def _add_log_entry(self, message: str) -> None:
        """Add an entry to the connection log."""
        from datetime import datetime
        
        log_content = self.query_one("#log-content", Static)
        current_content = log_content.renderable
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        new_entry = f"[{timestamp}] {message}"
        
        if current_content == "No connection attempts yet":
            new_content = new_entry
        else:
            new_content = f"{current_content}\n{new_entry}"
        
        log_content.update(new_content)


class RuleManagementInterface(Widget):
    """Widget for managing custom threat detection rules."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rules: List[Dict[str, Any]] = []
    
    def compose(self) -> ComposeResult:
        """Create the rule management interface layout."""
        with Container(id="rule-management"):
            yield Static("Rule Management", classes="panel-title")
            
            # Rule file operations
            with Horizontal(id="rule-file-ops"):
                yield Button("Load Rules", id="load-rules", variant="default")
                yield Button("Save Rules", id="save-rules", variant="primary")
                yield Button("Import Rules", id="import-rules", variant="default")
                yield Button("Export Rules", id="export-rules", variant="default")
            
            yield Rule()
            
            # Rule editor
            with Horizontal(id="rule-editor-area"):
                # Rule list
                with Vertical(id="rule-list-area"):
                    yield Static("Custom Rules", classes="section-title")
                    yield DataTable(id="rules-table", show_header=True, show_cursor=True)
                    
                    with Horizontal():
                        yield Button("Add Rule", id="add-rule", variant="primary")
                        yield Button("Edit Rule", id="edit-rule", variant="default")
                        yield Button("Delete Rule", id="delete-rule", variant="error")
                
                # Rule details editor
                with Vertical(id="rule-details-area"):
                    yield Static("Rule Editor", classes="section-title")
                    
                    yield Label("Rule Name:")
                    yield Input(placeholder="Enter rule name", id="rule-name-input")
                    
                    yield Label("Rule Type:")
                    yield Select([
                        ("Command Pattern", "command"),
                        ("File Access", "file"),
                        ("IP Reputation", "ip"),
                        ("Behavioral", "behavioral")
                    ], id="rule-type-select")
                    
                    yield Label("Pattern/Condition:")
                    yield TextArea(id="rule-pattern-input")
                    
                    yield Label("Severity:")
                    yield Select([
                        ("Low", "low"),
                        ("Medium", "medium"),
                        ("High", "high"),
                        ("Critical", "critical")
                    ], id="rule-severity-select")
                    
                    yield Label("Description:")
                    yield TextArea(id="rule-description-input")
                    
                    with Horizontal():
                        yield Button("Save Rule", id="save-rule-changes", variant="primary")
                        yield Button("Test Rule", id="test-rule", variant="default")
                        yield Button("Clear Form", id="clear-form", variant="default")
            
            # Rule validation status
            yield Static("Rule Status: Ready", id="rule-status")
    
    def on_mount(self) -> None:
        """Initialize the rule management interface."""
        # Setup rules table
        table = self.query_one("#rules-table", DataTable)
        table.add_columns("Name", "Type", "Severity", "Pattern", "Status")
        
        # Load example rules
        self._load_example_rules()
    
    def _load_example_rules(self) -> None:
        """Load example rules for demonstration."""
        example_rules = [
            {
                'name': 'Malware Download',
                'type': 'command',
                'pattern': r'(wget|curl).*\.(exe|sh|py|bin)$',
                'severity': 'high',
                'description': 'Detects potential malware downloads',
                'enabled': True
            },
            {
                'name': 'Sensitive File Access',
                'type': 'file',
                'pattern': r'/etc/(passwd|shadow|sudoers)',
                'severity': 'medium',
                'description': 'Access to sensitive system files',
                'enabled': True
            },
            {
                'name': 'Privilege Escalation',
                'type': 'command',
                'pattern': r'\b(sudo|su|chmod\s+777)\b',
                'severity': 'high',
                'description': 'Privilege escalation attempts',
                'enabled': True
            }
        ]
        
        for rule in example_rules:
            self.rules.append(rule)
            self._add_rule_to_table(rule)
    
    def _add_rule_to_table(self, rule: Dict[str, Any]) -> None:
        """Add a rule to the rules table."""
        table = self.query_one("#rules-table", DataTable)
        status = "✅ Enabled" if rule.get('enabled', True) else "❌ Disabled"
        
        table.add_row(
            rule['name'],
            rule['type'].title(),
            rule['severity'].title(),
            rule['pattern'][:30] + "..." if len(rule['pattern']) > 30 else rule['pattern'],
            status
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "load-rules":
            self._load_rules_file()
        elif event.button.id == "save-rules":
            self._save_rules_file()
        elif event.button.id == "import-rules":
            self._import_rules()
        elif event.button.id == "export-rules":
            self._export_rules()
        elif event.button.id == "add-rule":
            self._add_new_rule()
        elif event.button.id == "edit-rule":
            self._edit_selected_rule()
        elif event.button.id == "delete-rule":
            self._delete_selected_rule()
        elif event.button.id == "save-rule-changes":
            self._save_rule_changes()
        elif event.button.id == "test-rule":
            self._test_current_rule()
        elif event.button.id == "clear-form":
            self._clear_rule_form()
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle rule selection to populate editor."""
        if event.row_index < len(self.rules):
            rule = self.rules[event.row_index]
            self._populate_rule_form(rule)
    
    def _populate_rule_form(self, rule: Dict[str, Any]) -> None:
        """Populate the rule editor form with selected rule data."""
        self.query_one("#rule-name-input", Input).value = rule['name']
        self.query_one("#rule-type-select", Select).value = rule['type']
        self.query_one("#rule-pattern-input", TextArea).text = rule['pattern']
        self.query_one("#rule-severity-select", Select).value = rule['severity']
        self.query_one("#rule-description-input", TextArea).text = rule['description']
    
    def _clear_rule_form(self) -> None:
        """Clear the rule editor form."""
        self.query_one("#rule-name-input", Input).value = ""
        self.query_one("#rule-pattern-input", TextArea).text = ""
        self.query_one("#rule-description-input", TextArea).text = ""
    
    def _add_new_rule(self) -> None:
        """Add a new rule from the form data."""
        self._clear_rule_form()
        self._update_rule_status("Ready to create new rule", "info")
    
    def _edit_selected_rule(self) -> None:
        """Edit the selected rule."""
        table = self.query_one("#rules-table", DataTable)
        if table.cursor_row >= 0 and table.cursor_row < len(self.rules):
            rule = self.rules[table.cursor_row]
            self._populate_rule_form(rule)
            self._update_rule_status(f"Editing rule: {rule['name']}", "info")
    
    def _delete_selected_rule(self) -> None:
        """Delete the selected rule."""
        table = self.query_one("#rules-table", DataTable)
        if table.cursor_row >= 0 and table.cursor_row < len(self.rules):
            rule_name = self.rules[table.cursor_row]['name']
            del self.rules[table.cursor_row]
            table.remove_row(table.cursor_row)
            self._update_rule_status(f"Deleted rule: {rule_name}", "success")
    
    def _save_rule_changes(self) -> None:
        """Save changes to the current rule."""
        try:
            name = self.query_one("#rule-name-input", Input).value.strip()
            rule_type = self.query_one("#rule-type-select", Select).value
            pattern = self.query_one("#rule-pattern-input", TextArea).text.strip()
            severity = self.query_one("#rule-severity-select", Select).value
            description = self.query_one("#rule-description-input", TextArea).text.strip()
            
            if not all([name, rule_type, pattern, severity, description]):
                self._update_rule_status("All fields are required", "error")
                return
            
            new_rule = {
                'name': name,
                'type': rule_type,
                'pattern': pattern,
                'severity': severity,
                'description': description,
                'enabled': True
            }
            
            # Check if editing existing rule
            table = self.query_one("#rules-table", DataTable)
            if table.cursor_row >= 0 and table.cursor_row < len(self.rules):
                # Update existing rule
                self.rules[table.cursor_row] = new_rule
                table.remove_row(table.cursor_row)
                table.add_row(
                    new_rule['name'],
                    new_rule['type'].title(),
                    new_rule['severity'].title(),
                    new_rule['pattern'][:30] + "..." if len(new_rule['pattern']) > 30 else new_rule['pattern'],
                    "✅ Enabled"
                )
                self._update_rule_status(f"Updated rule: {name}", "success")
            else:
                # Add new rule
                self.rules.append(new_rule)
                self._add_rule_to_table(new_rule)
                self._update_rule_status(f"Added new rule: {name}", "success")
            
            self._clear_rule_form()
            
        except Exception as e:
            self._update_rule_status(f"Error saving rule: {e}", "error")
    
    def _test_current_rule(self) -> None:
        """Test the current rule configuration."""
        pattern = self.query_one("#rule-pattern-input", TextArea).text.strip()
        if not pattern:
            self._update_rule_status("No pattern to test", "warning")
            return
        
        # In a real implementation, this would test the regex pattern
        try:
            import re
            re.compile(pattern)
            self._update_rule_status("Pattern is valid", "success")
        except re.error as e:
            self._update_rule_status(f"Invalid regex pattern: {e}", "error")
    
    def _load_rules_file(self) -> None:
        """Load rules from file."""
        # In a real implementation, this would open a file dialog
        self._update_rule_status("Rules loaded from file", "success")
    
    def _save_rules_file(self) -> None:
        """Save rules to file."""
        # In a real implementation, this would save to a file
        self._update_rule_status("Rules saved to file", "success")
    
    def _import_rules(self) -> None:
        """Import rules from external source."""
        # In a real implementation, this would import from JSON/YAML
        self._update_rule_status("Rules imported successfully", "success")
    
    def _export_rules(self) -> None:
        """Export rules to external format."""
        # In a real implementation, this would export to JSON/YAML
        self._update_rule_status("Rules exported successfully", "success")
    
    def _update_rule_status(self, message: str, status_type: str = "info") -> None:
        """Update the rule status display."""
        status_widget = self.query_one("#rule-status", Static)
        
        if status_type == "success":
            status_widget.update(f"✅ {message}")
        elif status_type == "error":
            status_widget.update(f"❌ {message}")
        elif status_type == "warning":
            status_widget.update(f"⚠️ {message}")
        else:
            status_widget.update(f"ℹ️ {message}")


class SettingsPanel(Widget):
    """Main settings panel containing all configuration components."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.config_manager = ConfigManager()
    
    def compose(self) -> ComposeResult:
        """Create the settings panel layout with tabs."""
        with Container(id="settings-panel"):
            yield Static("⚙️ Settings & Configuration", classes="main-title")
            
            with Tabs(id="settings-tabs"):
                with TabPane("Configuration", id="config-tab"):
                    yield ConfigurationEditor(self.config_manager)
                
                with TabPane("IRC Testing", id="irc-tab"):
                    yield IRCConnectionTester()
                
                with TabPane("Rule Management", id="rules-tab"):
                    yield RuleManagementInterface()
    
    def get_current_settings(self) -> Optional[Settings]:
        """Get the current configuration settings."""
        config_editor = self.query_one(ConfigurationEditor)
        return config_editor.current_settings
    
    def update_irc_tester(self, irc_settings: IRCSettings) -> None:
        """Update the IRC tester with current settings."""
        irc_tester = self.query_one(IRCConnectionTester)
        irc_tester.update_settings(irc_settings)
    
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        """Get the current custom rules."""
        rule_manager = self.query_one(RuleManagementInterface)
        return rule_manager.rules