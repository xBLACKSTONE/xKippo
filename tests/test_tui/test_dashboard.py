"""
Tests for dashboard components.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock

from honeypot_monitor.tui.dashboard import (
    ActivityFeed, ConnectionStats, AlertPanel, IRCStatusIndicator, Dashboard
)


class TestActivityFeed:
    """Test cases for the ActivityFeed widget."""
    
    def test_activity_feed_initialization(self):
        """Test that ActivityFeed initializes correctly."""
        feed = ActivityFeed()
        
        assert feed.id == "activity-feed"
        assert feed.max_entries == 100
        assert feed.entries == []
    
    def test_add_entry(self):
        """Test adding entries to the activity feed."""
        feed = ActivityFeed()
        timestamp = datetime.now()
        
        feed.add_entry(timestamp, "Test message", "info")
        
        assert len(feed.entries) == 1
        assert "Test message" in feed.entries[0]
        assert "ℹ" in feed.entries[0]  # Info indicator
    
    def test_max_entries_limit(self):
        """Test that activity feed respects max entries limit."""
        feed = ActivityFeed()
        feed.max_entries = 5
        
        # Add more entries than the limit
        for i in range(10):
            feed.add_entry(datetime.now(), f"Message {i}", "info")
        
        assert len(feed.entries) == 5
        assert "Message 9" in feed.entries[-1]  # Should keep the most recent
    
    def test_severity_indicators(self):
        """Test that different severity levels get correct indicators."""
        feed = ActivityFeed()
        
        indicators = {
            "info": "ℹ",
            "warning": "⚠",
            "error": "✗",
            "success": "✓",
            "critical": "🔥"
        }
        
        for severity, expected_indicator in indicators.items():
            result = feed._get_severity_indicator(severity)
            assert result == expected_indicator
        
        # Test unknown severity
        result = feed._get_severity_indicator("unknown")
        assert result == "•"


class TestConnectionStats:
    """Test cases for the ConnectionStats widget."""
    
    def test_connection_stats_initialization(self):
        """Test that ConnectionStats initializes correctly."""
        stats = ConnectionStats()
        
        assert stats.id == "connection-stats"
        assert stats.active_sessions == 0
        assert stats.total_connections == 0
        assert stats.unique_ips == 0
        assert stats.blocked_attempts == 0
    
    def test_update_stats(self):
        """Test updating all statistics at once."""
        stats = ConnectionStats()
        
        stats.update_stats(active=5, total=100, unique=25, blocked=10)
        
        assert stats.active_sessions == 5
        assert stats.total_connections == 100
        assert stats.unique_ips == 25
        assert stats.blocked_attempts == 10


class TestAlertPanel:
    """Test cases for the AlertPanel widget."""
    
    def test_alert_panel_initialization(self):
        """Test that AlertPanel initializes correctly."""
        panel = AlertPanel()
        
        assert panel.id == "alert-panel"
        assert panel.alerts == []
        assert panel.max_alerts == 10
    
    def test_add_alert(self):
        """Test adding alerts to the panel."""
        panel = AlertPanel()
        
        panel.add_alert("Test alert", "warning")
        
        assert len(panel.alerts) == 1
        assert panel.alerts[0]["message"] == "Test alert"
        assert panel.alerts[0]["severity"] == "warning"
        assert "timestamp" in panel.alerts[0]
    
    def test_max_alerts_limit(self):
        """Test that alert panel respects max alerts limit."""
        panel = AlertPanel()
        panel.max_alerts = 3
        
        # Add more alerts than the limit
        for i in range(5):
            panel.add_alert(f"Alert {i}", "info")
        
        assert len(panel.alerts) == 3
        assert panel.alerts[-1]["message"] == "Alert 4"  # Should keep the most recent
    
    def test_clear_alerts(self):
        """Test clearing all alerts."""
        panel = AlertPanel()
        
        panel.add_alert("Test alert 1", "info")
        panel.add_alert("Test alert 2", "warning")
        
        assert len(panel.alerts) == 2
        
        panel.clear_alerts()
        
        assert len(panel.alerts) == 0


class TestIRCStatusIndicator:
    """Test cases for the IRCStatusIndicator widget."""
    
    def test_irc_status_initialization(self):
        """Test that IRCStatusIndicator initializes correctly."""
        indicator = IRCStatusIndicator()
        
        assert indicator.id == "irc-status"
        assert indicator.connection_status == "Disconnected"
        assert indicator.server_info == ""
        assert indicator.last_message_time == ""
    
    def test_update_status(self):
        """Test updating IRC status information."""
        indicator = IRCStatusIndicator()
        
        indicator.update_status(
            status="Connected",
            server="irc.example.com:6667",
            last_message="5 minutes ago"
        )
        
        assert indicator.connection_status == "Connected"
        assert indicator.server_info == "irc.example.com:6667"
        assert indicator.last_message_time == "5 minutes ago"


class TestDashboard:
    """Test cases for the Dashboard container."""
    
    def test_dashboard_initialization(self):
        """Test that Dashboard initializes correctly."""
        dashboard = Dashboard()
        
        assert dashboard.id == "dashboard"
        assert dashboard.activity_feed is None
        assert dashboard.connection_stats is None
        assert dashboard.alert_panel is None
        assert dashboard.irc_status is None
    
    def test_dashboard_compose_method_exists(self):
        """Test that dashboard has a compose method."""
        dashboard = Dashboard()
        
        # Just verify the method exists and is callable
        assert hasattr(dashboard, 'compose')
        assert callable(dashboard.compose)
    
    def test_add_activity(self):
        """Test adding activity through dashboard interface."""
        dashboard = Dashboard()
        dashboard.activity_feed = Mock()
        
        dashboard.add_activity("Test activity", "info")
        
        dashboard.activity_feed.add_entry.assert_called_once()
    
    def test_add_alert(self):
        """Test adding alert through dashboard interface."""
        dashboard = Dashboard()
        dashboard.alert_panel = Mock()
        
        dashboard.add_alert("Test alert", "warning")
        
        dashboard.alert_panel.add_alert.assert_called_once_with("Test alert", "warning")
    
    def test_update_connection_stats(self):
        """Test updating connection stats through dashboard interface."""
        dashboard = Dashboard()
        dashboard.connection_stats = Mock()
        
        dashboard.update_connection_stats(5, 100, 25, 10)
        
        dashboard.connection_stats.update_stats.assert_called_once_with(5, 100, 25, 10)
    
    def test_update_irc_status(self):
        """Test updating IRC status through dashboard interface."""
        dashboard = Dashboard()
        dashboard.irc_status = Mock()
        
        dashboard.update_irc_status("Connected", "server.com", "now")
        
        dashboard.irc_status.update_status.assert_called_once_with("Connected", "server.com", "now")


class TestDashboardIntegration:
    """Integration tests for dashboard components."""
    
    @pytest.mark.asyncio
    async def test_full_dashboard_workflow(self):
        """Test complete dashboard workflow with all components."""
        dashboard = Dashboard()
        
        # This would normally be done by textual during compose
        dashboard.activity_feed = ActivityFeed()
        dashboard.connection_stats = ConnectionStats()
        dashboard.alert_panel = AlertPanel()
        dashboard.irc_status = IRCStatusIndicator()
        
        # Test adding various data
        dashboard.add_activity("Connection established", "success")
        dashboard.add_alert("Security warning", "warning")
        dashboard.update_connection_stats(3, 50, 15, 5)
        dashboard.update_irc_status("Connected", "irc.test.com", "1 min ago")
        
        # Verify data was added
        assert len(dashboard.activity_feed.entries) == 1
        assert len(dashboard.alert_panel.alerts) == 1
        assert dashboard.connection_stats.active_sessions == 3
        assert dashboard.irc_status.connection_status == "Connected"