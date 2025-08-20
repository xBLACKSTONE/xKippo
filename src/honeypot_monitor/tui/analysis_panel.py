"""
Analysis panel TUI component for threat analysis and pattern detection.

This module provides the analysis interface for viewing threat categorization,
pattern analysis results, custom rule configuration, and threat history tracking.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Static, DataTable, ProgressBar, Button, Input, Select, 
    Collapsible, Label, Rule, Tabs, TabPane
)
from textual.widget import Widget
from textual.reactive import reactive
from textual.message import Message
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from ..models.threat_assessment import ThreatAssessment
from ..models.log_entry import LogEntry


class ThreatCategoryDisplay(Widget):
    """Widget for displaying threat categorization with severity indicators."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data: Dict[str, List[ThreatAssessment]] = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
    
    def compose(self) -> ComposeResult:
        """Create the threat category display layout."""
        with Container(id="threat-categories"):
            yield Static("Threat Categories", classes="panel-title")
            
            # Critical threats
            with Collapsible(title="🔴 Critical Threats (0)", id="critical-threats"):
                yield DataTable(id="critical-table", show_header=True, show_cursor=False)
            
            # High threats
            with Collapsible(title="🟠 High Threats (0)", id="high-threats"):
                yield DataTable(id="high-table", show_header=True, show_cursor=False)
            
            # Medium threats
            with Collapsible(title="🟡 Medium Threats (0)", id="medium-threats"):
                yield DataTable(id="medium-table", show_header=True, show_cursor=False)
            
            # Low threats
            with Collapsible(title="🟢 Low Threats (0)", id="low-threats"):
                yield DataTable(id="low-table", show_header=True, show_cursor=False)
    
    def on_mount(self) -> None:
        """Initialize the data tables."""
        # Setup table headers for all severity levels
        for severity in ['critical', 'high', 'medium', 'low']:
            table = self.query_one(f"#{severity}-table", DataTable)
            table.add_columns("Time", "Category", "Confidence", "Indicators", "Action")
    
    def add_threat(self, threat: ThreatAssessment, timestamp: datetime) -> None:
        """Add a threat assessment to the appropriate category."""
        self.threat_data[threat.severity].append(threat)
        
        # Update the table
        table = self.query_one(f"#{threat.severity}-table", DataTable)
        indicators_str = ", ".join(threat.indicators[:3])  # Show first 3 indicators
        if len(threat.indicators) > 3:
            indicators_str += f" (+{len(threat.indicators) - 3} more)"
        
        table.add_row(
            timestamp.strftime("%H:%M:%S"),
            threat.category.title(),
            f"{threat.confidence:.2f}",
            indicators_str,
            threat.recommended_action[:50] + "..." if len(threat.recommended_action) > 50 else threat.recommended_action
        )
        
        # Update collapsible title with count
        collapsible = self.query_one(f"#{threat.severity}-threats", Collapsible)
        count = len(self.threat_data[threat.severity])
        severity_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
        collapsible.title = f"{severity_icons[threat.severity]} {threat.severity.title()} Threats ({count})"
    
    def clear_threats(self) -> None:
        """Clear all threat data."""
        for severity in ['critical', 'high', 'medium', 'low']:
            self.threat_data[severity].clear()
            table = self.query_one(f"#{severity}-table", DataTable)
            table.clear()
            
            # Reset collapsible titles
            collapsible = self.query_one(f"#{severity}-threats", Collapsible)
            severity_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
            collapsible.title = f"{severity_icons[severity]} {severity.title()} Threats (0)"


class PatternAnalysisViewer(Widget):
    """Widget for displaying pattern analysis results with trend visualization."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patterns: List[Dict[str, Any]] = []
    
    def compose(self) -> ComposeResult:
        """Create the pattern analysis viewer layout."""
        with Container(id="pattern-analysis"):
            yield Static("Pattern Analysis", classes="panel-title")
            
            # Pattern summary
            with Horizontal(id="pattern-summary"):
                yield Static("Total Patterns: 0", id="pattern-count")
                yield Static("Active Threats: 0", id="active-threats")
                yield Static("Trend: ↔️ Stable", id="trend-indicator")
            
            yield Rule()
            
            # Pattern details table
            yield DataTable(id="patterns-table", show_header=True, show_cursor=True)
            
            # Pattern details view
            with Collapsible(title="Pattern Details", collapsed=True, id="pattern-details"):
                yield Static("Select a pattern to view details", id="pattern-detail-text")
    
    def on_mount(self) -> None:
        """Initialize the patterns table."""
        table = self.query_one("#patterns-table", DataTable)
        table.add_columns("Type", "Severity", "Confidence", "Description", "Count", "Time Span")
    
    def add_pattern(self, pattern: Dict[str, Any]) -> None:
        """Add a detected pattern to the viewer."""
        self.patterns.append(pattern)
        
        # Update the table
        table = self.query_one("#patterns-table", DataTable)
        
        # Format time span if available
        time_span = ""
        if 'time_span' in pattern:
            time_span = f"{pattern['time_span']:.0f}s"
        elif 'time_span_hours' in pattern:
            time_span = f"{pattern['time_span_hours']:.1f}h"
        
        table.add_row(
            pattern.get('type', 'Unknown').replace('_', ' ').title(),
            pattern.get('severity', 'Unknown').title(),
            f"{pattern.get('confidence', 0):.2f}",
            pattern.get('description', 'No description')[:60],
            str(pattern.get('event_count', pattern.get('entry_count', 'N/A'))),
            time_span
        )
        
        # Update summary
        self._update_summary()
    
    def _update_summary(self) -> None:
        """Update the pattern summary statistics."""
        total_patterns = len(self.patterns)
        active_threats = len([p for p in self.patterns if p.get('severity') in ['high', 'critical']])
        
        # Update display
        self.query_one("#pattern-count", Static).update(f"Total Patterns: {total_patterns}")
        self.query_one("#active-threats", Static).update(f"Active Threats: {active_threats}")
        
        # Simple trend calculation (would be more sophisticated in production)
        if total_patterns > 10:
            recent_patterns = self.patterns[-5:]
            recent_threats = len([p for p in recent_patterns if p.get('severity') in ['high', 'critical']])
            if recent_threats > 2:
                trend = "📈 Increasing"
            elif recent_threats == 0:
                trend = "📉 Decreasing"
            else:
                trend = "↔️ Stable"
        else:
            trend = "↔️ Stable"
        
        self.query_one("#trend-indicator", Static).update(f"Trend: {trend}")
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle pattern selection to show details."""
        if event.row_index < len(self.patterns):
            pattern = self.patterns[event.row_index]
            self._show_pattern_details(pattern)
    
    def _show_pattern_details(self, pattern: Dict[str, Any]) -> None:
        """Show detailed information about a selected pattern."""
        details = f"""
Pattern Type: {pattern.get('type', 'Unknown').replace('_', ' ').title()}
Severity: {pattern.get('severity', 'Unknown').title()}
Confidence: {pattern.get('confidence', 0):.2f}
Description: {pattern.get('description', 'No description')}

Indicators:
{chr(10).join(f"• {indicator}" for indicator in pattern.get('indicators', []))}

Additional Information:
"""
        
        # Add type-specific information
        if 'source_ip' in pattern:
            details += f"Source IP: {pattern['source_ip']}\n"
        if 'session_id' in pattern:
            details += f"Session ID: {pattern['session_id']}\n"
        if 'event_count' in pattern:
            details += f"Event Count: {pattern['event_count']}\n"
        if 'time_span' in pattern:
            details += f"Time Span: {pattern['time_span']:.0f} seconds\n"
        if 'time_span_hours' in pattern:
            details += f"Duration: {pattern['time_span_hours']:.1f} hours\n"
        
        self.query_one("#pattern-detail-text", Static).update(details.strip())
        
        # Expand the details section
        collapsible = self.query_one("#pattern-details", Collapsible)
        collapsible.collapsed = False
    
    def clear_patterns(self) -> None:
        """Clear all pattern data."""
        self.patterns.clear()
        table = self.query_one("#patterns-table", DataTable)
        table.clear()
        self._update_summary()


class CustomRuleConfig(Widget):
    """Widget for configuring custom threat detection rules."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.custom_rules: List[Dict[str, Any]] = []
    
    def compose(self) -> ComposeResult:
        """Create the custom rule configuration layout."""
        with Container(id="custom-rules"):
            yield Static("Custom Rules Configuration", classes="panel-title")
            
            # Rule creation form
            with Collapsible(title="Create New Rule", id="rule-creator"):
                with Vertical():
                    yield Label("Rule Name:")
                    yield Input(placeholder="Enter rule name", id="rule-name")
                    
                    yield Label("Rule Type:")
                    yield Select([
                        ("Command Pattern", "command"),
                        ("File Access", "file"),
                        ("IP Reputation", "ip"),
                        ("Behavioral", "behavioral")
                    ], id="rule-type")
                    
                    yield Label("Pattern/Condition:")
                    yield Input(placeholder="Enter regex pattern or condition", id="rule-pattern")
                    
                    yield Label("Severity:")
                    yield Select([
                        ("Low", "low"),
                        ("Medium", "medium"),
                        ("High", "high"),
                        ("Critical", "critical")
                    ], id="rule-severity")
                    
                    yield Label("Description:")
                    yield Input(placeholder="Describe what this rule detects", id="rule-description")
                    
                    with Horizontal():
                        yield Button("Add Rule", id="add-rule", variant="primary")
                        yield Button("Test Rule", id="test-rule", variant="default")
            
            yield Rule()
            
            # Existing rules table
            yield Static("Active Rules", classes="section-title")
            yield DataTable(id="rules-table", show_header=True, show_cursor=True)
            
            with Horizontal():
                yield Button("Edit Selected", id="edit-rule", variant="default")
                yield Button("Delete Selected", id="delete-rule", variant="error")
                yield Button("Export Rules", id="export-rules", variant="default")
                yield Button("Import Rules", id="import-rules", variant="default")
    
    def on_mount(self) -> None:
        """Initialize the rules table."""
        table = self.query_one("#rules-table", DataTable)
        table.add_columns("Name", "Type", "Severity", "Pattern", "Description", "Status")
        
        # Load some example rules
        self._load_example_rules()
    
    def _load_example_rules(self) -> None:
        """Load example custom rules for demonstration."""
        example_rules = [
            {
                'name': 'Suspicious Downloads',
                'type': 'command',
                'pattern': r'(wget|curl).*\.(sh|py|exe|bin)$',
                'severity': 'high',
                'description': 'Detects downloads of potentially malicious files',
                'enabled': True
            },
            {
                'name': 'Root Directory Access',
                'type': 'file',
                'pattern': r'^/root/',
                'severity': 'medium',
                'description': 'Detects access to root user directory',
                'enabled': True
            },
            {
                'name': 'Known Bad IPs',
                'type': 'ip',
                'pattern': '192.168.100.0/24',
                'severity': 'critical',
                'description': 'Connections from known malicious IP range',
                'enabled': False
            }
        ]
        
        for rule in example_rules:
            self.custom_rules.append(rule)
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
            rule['description'][:40] + "..." if len(rule['description']) > 40 else rule['description'],
            status
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "add-rule":
            self._add_new_rule()
        elif event.button.id == "test-rule":
            self._test_rule()
        elif event.button.id == "edit-rule":
            self._edit_selected_rule()
        elif event.button.id == "delete-rule":
            self._delete_selected_rule()
        elif event.button.id == "export-rules":
            self._export_rules()
        elif event.button.id == "import-rules":
            self._import_rules()
    
    def _add_new_rule(self) -> None:
        """Add a new custom rule."""
        try:
            name = self.query_one("#rule-name", Input).value.strip()
            rule_type = self.query_one("#rule-type", Select).value
            pattern = self.query_one("#rule-pattern", Input).value.strip()
            severity = self.query_one("#rule-severity", Select).value
            description = self.query_one("#rule-description", Input).value.strip()
            
            if not all([name, rule_type, pattern, severity, description]):
                # In a real app, show an error message
                return
            
            new_rule = {
                'name': name,
                'type': rule_type,
                'pattern': pattern,
                'severity': severity,
                'description': description,
                'enabled': True,
                'created': datetime.now().isoformat()
            }
            
            self.custom_rules.append(new_rule)
            self._add_rule_to_table(new_rule)
            
            # Clear the form
            self.query_one("#rule-name", Input).value = ""
            self.query_one("#rule-pattern", Input).value = ""
            self.query_one("#rule-description", Input).value = ""
            
        except Exception as e:
            # In a real app, show error message to user
            pass
    
    def _test_rule(self) -> None:
        """Test the current rule configuration."""
        # In a real implementation, this would test the rule against sample data
        pass
    
    def _edit_selected_rule(self) -> None:
        """Edit the selected rule."""
        # In a real implementation, this would populate the form with selected rule data
        pass
    
    def _delete_selected_rule(self) -> None:
        """Delete the selected rule."""
        table = self.query_one("#rules-table", DataTable)
        if table.cursor_row >= 0 and table.cursor_row < len(self.custom_rules):
            # Remove from data and table
            del self.custom_rules[table.cursor_row]
            table.remove_row(table.cursor_row)
    
    def _export_rules(self) -> None:
        """Export rules to JSON format."""
        # In a real implementation, this would save rules to a file
        pass
    
    def _import_rules(self) -> None:
        """Import rules from JSON format."""
        # In a real implementation, this would load rules from a file
        pass


class ThreatHistoryTracker(Widget):
    """Widget for displaying threat history and tracking."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_history: List[Dict[str, Any]] = []
    
    def compose(self) -> ComposeResult:
        """Create the threat history tracker layout."""
        with Container(id="threat-history"):
            yield Static("Threat History & Tracking", classes="panel-title")
            
            # Time range selector
            with Horizontal(id="time-controls"):
                yield Static("Time Range:")
                yield Select([
                    ("Last Hour", "1h"),
                    ("Last 6 Hours", "6h"),
                    ("Last 24 Hours", "24h"),
                    ("Last Week", "7d"),
                    ("All Time", "all")
                ], value="24h", id="time-range")
                yield Button("Refresh", id="refresh-history", variant="default")
            
            # Statistics summary
            with Horizontal(id="history-stats"):
                yield Static("Total Threats: 0", id="total-threats")
                yield Static("Unique IPs: 0", id="unique-ips")
                yield Static("Most Active: N/A", id="most-active-ip")
            
            yield Rule()
            
            # History table
            yield DataTable(id="history-table", show_header=True, show_cursor=True)
            
            # Threat timeline (simplified text representation)
            with Collapsible(title="Threat Timeline", collapsed=True, id="threat-timeline"):
                yield ScrollableContainer(
                    Static("No threat data available", id="timeline-content"),
                    id="timeline-scroll"
                )
    
    def on_mount(self) -> None:
        """Initialize the history table."""
        table = self.query_one("#history-table", DataTable)
        table.add_columns("Time", "Source IP", "Severity", "Category", "Description", "Status")
        
        # Load some example history data
        self._load_example_history()
    
    def _load_example_history(self) -> None:
        """Load example threat history for demonstration."""
        example_threats = [
            {
                'timestamp': datetime.now() - timedelta(minutes=5),
                'source_ip': '192.168.1.100',
                'severity': 'high',
                'category': 'exploitation',
                'description': 'Privilege escalation attempt detected',
                'status': 'active'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=15),
                'source_ip': '10.0.0.5',
                'severity': 'medium',
                'category': 'reconnaissance',
                'description': 'System enumeration commands',
                'status': 'resolved'
            },
            {
                'timestamp': datetime.now() - timedelta(hours=1),
                'source_ip': '172.16.0.10',
                'severity': 'critical',
                'category': 'persistence',
                'description': 'Backdoor creation attempt',
                'status': 'investigating'
            }
        ]
        
        for threat in example_threats:
            self.threat_history.append(threat)
            self._add_threat_to_history(threat)
        
        self._update_statistics()
    
    def _add_threat_to_history(self, threat: Dict[str, Any]) -> None:
        """Add a threat to the history table."""
        table = self.query_one("#history-table", DataTable)
        
        status_icons = {
            'active': '🔴',
            'investigating': '🟡',
            'resolved': '✅',
            'ignored': '⚪'
        }
        
        table.add_row(
            threat['timestamp'].strftime("%m/%d %H:%M"),
            threat['source_ip'],
            threat['severity'].title(),
            threat['category'].title(),
            threat['description'][:50] + "..." if len(threat['description']) > 50 else threat['description'],
            f"{status_icons.get(threat['status'], '❓')} {threat['status'].title()}"
        )
    
    def _update_statistics(self) -> None:
        """Update the threat history statistics."""
        total_threats = len(self.threat_history)
        unique_ips = len(set(threat['source_ip'] for threat in self.threat_history))
        
        # Find most active IP
        if self.threat_history:
            ip_counts = {}
            for threat in self.threat_history:
                ip = threat['source_ip']
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            most_active = max(ip_counts.items(), key=lambda x: x[1])
            most_active_str = f"{most_active[0]} ({most_active[1]} threats)"
        else:
            most_active_str = "N/A"
        
        # Update display
        self.query_one("#total-threats", Static).update(f"Total Threats: {total_threats}")
        self.query_one("#unique-ips", Static).update(f"Unique IPs: {unique_ips}")
        self.query_one("#most-active-ip", Static).update(f"Most Active: {most_active_str}")
    
    def add_threat_event(self, threat: ThreatAssessment, source_ip: str, description: str) -> None:
        """Add a new threat event to the history."""
        threat_event = {
            'timestamp': datetime.now(),
            'source_ip': source_ip,
            'severity': threat.severity,
            'category': threat.category,
            'description': description,
            'status': 'active'
        }
        
        self.threat_history.append(threat_event)
        self._add_threat_to_history(threat_event)
        self._update_statistics()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "refresh-history":
            self._refresh_history()
    
    def _refresh_history(self) -> None:
        """Refresh the threat history display."""
        # In a real implementation, this would reload data based on time range
        pass


class AnalysisPanel(Widget):
    """Main analysis panel containing all threat analysis components."""
    
    def compose(self) -> ComposeResult:
        """Create the analysis panel layout with tabs."""
        with Container(id="analysis-panel"):
            yield Static("🔍 Threat Analysis Dashboard", classes="main-title")
            
            with Tabs(id="analysis-tabs"):
                with TabPane("Threat Categories", id="categories-tab"):
                    yield ThreatCategoryDisplay()
                
                with TabPane("Pattern Analysis", id="patterns-tab"):
                    yield PatternAnalysisViewer()
                
                with TabPane("Custom Rules", id="rules-tab"):
                    yield CustomRuleConfig()
                
                with TabPane("Threat History", id="history-tab"):
                    yield ThreatHistoryTracker()
    
    def add_threat_assessment(self, threat: ThreatAssessment, source_ip: str, description: str) -> None:
        """Add a threat assessment to the appropriate displays."""
        timestamp = datetime.now()
        
        # Add to threat categories
        threat_display = self.query_one(ThreatCategoryDisplay)
        threat_display.add_threat(threat, timestamp)
        
        # Add to threat history
        history_tracker = self.query_one(ThreatHistoryTracker)
        history_tracker.add_threat_event(threat, source_ip, description)
    
    def add_pattern(self, pattern: Dict[str, Any]) -> None:
        """Add a detected pattern to the pattern analysis viewer."""
        pattern_viewer = self.query_one(PatternAnalysisViewer)
        pattern_viewer.add_pattern(pattern)
    
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        """Get the current custom rules configuration."""
        rule_config = self.query_one(CustomRuleConfig)
        return rule_config.custom_rules
    
    def clear_all_data(self) -> None:
        """Clear all analysis data."""
        threat_display = self.query_one(ThreatCategoryDisplay)
        threat_display.clear_threats()
        
        pattern_viewer = self.query_one(PatternAnalysisViewer)
        pattern_viewer.clear_patterns()