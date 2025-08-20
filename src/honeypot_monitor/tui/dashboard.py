"""
Dashboard components for the Honeypot Monitor CLI.

This module provides the main dashboard interface with real-time activity feed,
connection statistics, alert notifications, and IRC status indicators.
"""

from datetime import datetime
from typing import List, Optional
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static
from textual.reactive import reactive
from textual.widget import Widget


class ActivityFeed(Container):
    """Real-time activity feed widget with scrolling log display."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = "activity-feed"
        self.max_entries = 100
        self.entries: List[str] = []
    
    def compose(self):
        """Create the activity feed layout."""
        with Vertical():
            yield Static("Recent Activity", classes="panel-title")
            yield Container(id="activity-content")
    
    def add_entry(self, timestamp: datetime, message: str, severity: str = "info") -> None:
        """Add a new activity entry to the feed."""
        time_str = timestamp.strftime("%H:%M:%S")
        severity_indicator = self._get_severity_indicator(severity)
        entry = f"{time_str} {severity_indicator} {message}"
        
        self.entries.append(entry)
        
        # Keep only the most recent entries
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]
        
        self._update_display()
    
    def _get_severity_indicator(self, severity: str) -> str:
        """Get colored indicator for severity level."""
        indicators = {
            "info": "ℹ",
            "warning": "⚠",
            "error": "✗",
            "success": "✓",
            "critical": "🔥"
        }
        return indicators.get(severity, "•")
    
    def _update_display(self) -> None:
        """Update the display with current entries."""
        try:
            content_container = self.query_one("#activity-content")
            content_container.remove_children()
            
            # Add entries as individual Static widgets
            for entry in self.entries[-20:]:  # Show last 20 entries
                content_container.mount(Static(entry, classes="activity-entry"))
        except:
            pass  # Widget might not be mounted yet


class ConnectionStats(Widget):
    """Connection statistics panel showing current session counts."""
    
    # Reactive attributes for real-time updates
    active_sessions = reactive(0)
    total_connections = reactive(0)
    unique_ips = reactive(0)
    blocked_attempts = reactive(0)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = "connection-stats"
    
    def compose(self):
        """Create the connection statistics layout."""
        with Vertical():
            yield Static("Connection Statistics", classes="panel-title")
            with Container(id="stats-content"):
                yield Static(f"Active Sessions: {self.active_sessions}", id="active-sessions")
                yield Static(f"Total Connections: {self.total_connections}", id="total-connections")
                yield Static(f"Unique IPs: {self.unique_ips}", id="unique-ips")
                yield Static(f"Blocked Attempts: {self.blocked_attempts}", id="blocked-attempts")
    
    def watch_active_sessions(self, new_value: int) -> None:
        """Update active sessions display."""
        try:
            widget = self.query_one("#active-sessions")
            widget.update(f"Active Sessions: {new_value}")
        except:
            pass
    
    def watch_total_connections(self, new_value: int) -> None:
        """Update total connections display."""
        try:
            widget = self.query_one("#total-connections")
            widget.update(f"Total Connections: {new_value}")
        except:
            pass
    
    def watch_unique_ips(self, new_value: int) -> None:
        """Update unique IPs display."""
        try:
            widget = self.query_one("#unique-ips")
            widget.update(f"Unique IPs: {new_value}")
        except:
            pass
    
    def watch_blocked_attempts(self, new_value: int) -> None:
        """Update blocked attempts display."""
        try:
            widget = self.query_one("#blocked-attempts")
            widget.update(f"Blocked Attempts: {new_value}")
        except:
            pass
    
    def update_stats(self, active: int, total: int, unique: int, blocked: int) -> None:
        """Update all statistics at once."""
        self.active_sessions = active
        self.total_connections = total
        self.unique_ips = unique
        self.blocked_attempts = blocked


class AlertPanel(Widget):
    """Alert notification area with color-coded severity."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = "alert-panel"
        self.alerts: List[dict] = []
        self.max_alerts = 10
    
    def compose(self):
        """Create the alert panel layout."""
        with Vertical():
            yield Static("Security Alerts", classes="panel-title")
            yield Container(id="alerts-content")
    
    def add_alert(self, message: str, severity: str = "info", timestamp: Optional[datetime] = None) -> None:
        """Add a new alert to the panel."""
        if timestamp is None:
            timestamp = datetime.now()
        
        alert = {
            "message": message,
            "severity": severity,
            "timestamp": timestamp,
            "time_str": timestamp.strftime("%H:%M:%S")
        }
        
        self.alerts.append(alert)
        
        # Keep only the most recent alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        self._update_display()
    
    def _update_display(self) -> None:
        """Update the alert display."""
        try:
            content_container = self.query_one("#alerts-content")
            content_container.remove_children()
            
            if not self.alerts:
                content_container.mount(Static("No active alerts", classes="no-alerts"))
                return
            
            # Show most recent alerts first
            for alert in reversed(self.alerts[-5:]):  # Show last 5 alerts
                severity_class = f"alert-{alert['severity']}"
                alert_text = f"{alert['time_str']} - {alert['message']}"
                content_container.mount(Static(alert_text, classes=f"alert-entry {severity_class}"))
        except:
            pass  # Widget might not be mounted yet
    
    def clear_alerts(self) -> None:
        """Clear all alerts."""
        self.alerts.clear()
        self._update_display()


class IRCStatusIndicator(Widget):
    """IRC connection status indicator."""
    
    # Reactive attributes
    connection_status = reactive("Disconnected")
    server_info = reactive("")
    last_message_time = reactive("")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = "irc-status"
    
    def compose(self):
        """Create the IRC status layout."""
        with Vertical():
            yield Static("IRC Status", classes="panel-title")
            with Container(id="irc-content"):
                yield Static(f"Status: {self.connection_status}", id="irc-connection")
                yield Static(f"Server: {self.server_info}", id="irc-server")
                yield Static(f"Last Message: {self.last_message_time}", id="irc-last-message")
    
    def watch_connection_status(self, new_status: str) -> None:
        """Update connection status display."""
        try:
            widget = self.query_one("#irc-connection")
            status_indicator = "🟢" if new_status == "Connected" else "🔴"
            widget.update(f"Status: {status_indicator} {new_status}")
        except:
            pass
    
    def watch_server_info(self, new_info: str) -> None:
        """Update server info display."""
        try:
            widget = self.query_one("#irc-server")
            widget.update(f"Server: {new_info}")
        except:
            pass
    
    def watch_last_message_time(self, new_time: str) -> None:
        """Update last message time display."""
        try:
            widget = self.query_one("#irc-last-message")
            widget.update(f"Last Message: {new_time}")
        except:
            pass
    
    def update_status(self, status: str, server: str = "", last_message: str = "") -> None:
        """Update all IRC status information."""
        self.connection_status = status
        if server:
            self.server_info = server
        if last_message:
            self.last_message_time = last_message


class Dashboard(Container):
    """Main dashboard container with all components."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = "dashboard"
        
        # Component references
        self.activity_feed: Optional[ActivityFeed] = None
        self.connection_stats: Optional[ConnectionStats] = None
        self.alert_panel: Optional[AlertPanel] = None
        self.irc_status: Optional[IRCStatusIndicator] = None
    
    def compose(self):
        """Create the dashboard layout."""
        with Horizontal():
            # Left column - Activity feed and alerts
            with Vertical(classes="dashboard-left"):
                self.activity_feed = ActivityFeed()
                yield self.activity_feed
                
                self.alert_panel = AlertPanel()
                yield self.alert_panel
            
            # Right column - Statistics and IRC status
            with Vertical(classes="dashboard-right"):
                self.connection_stats = ConnectionStats()
                yield self.connection_stats
                
                self.irc_status = IRCStatusIndicator()
                yield self.irc_status
    
    def add_activity(self, message: str, severity: str = "info") -> None:
        """Add activity to the feed."""
        if self.activity_feed:
            self.activity_feed.add_entry(datetime.now(), message, severity)
    
    def add_alert(self, message: str, severity: str = "info") -> None:
        """Add alert to the panel."""
        if self.alert_panel:
            self.alert_panel.add_alert(message, severity)
    
    def update_connection_stats(self, active: int, total: int, unique: int, blocked: int) -> None:
        """Update connection statistics."""
        if self.connection_stats:
            self.connection_stats.update_stats(active, total, unique, blocked)
    
    def update_irc_status(self, status: str, server: str = "", last_message: str = "") -> None:
        """Update IRC status."""
        if self.irc_status:
            self.irc_status.update_status(status, server, last_message)