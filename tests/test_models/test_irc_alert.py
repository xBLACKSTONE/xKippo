"""
Unit tests for IRCAlert model.
"""

import pytest
from datetime import datetime, timedelta
from src.honeypot_monitor.models.irc_alert import IRCAlert


class TestIRCAlert:
    """Test cases for IRCAlert model."""
    
    def test_valid_irc_alert_creation(self):
        """Test creating a valid IRC alert."""
        timestamp = datetime.now()
        alert = IRCAlert(
            alert_type="high_threat",
            timestamp=timestamp,
            source_ip="192.168.1.100",
            message="Suspicious activity detected",
            severity="high"
        )
        
        assert alert.alert_type == "high_threat"
        assert alert.timestamp == timestamp
        assert alert.source_ip == "192.168.1.100"
        assert alert.message == "Suspicious activity detected"
        assert alert.severity == "high"
        assert alert.sent is False
    
    def test_irc_alert_with_sent_flag(self):
        """Test creating an IRC alert with sent flag."""
        alert = IRCAlert(
            alert_type="new_host",
            timestamp=datetime.now(),
            source_ip="10.0.0.1",
            message="New host detected",
            severity="medium",
            sent=True
        )
        
        assert alert.sent is True
    
    def test_invalid_alert_type_validation(self):
        """Test validation fails for invalid alert_type."""
        with pytest.raises(ValueError, match="Invalid alert_type"):
            IRCAlert(
                alert_type="invalid_type",
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                message="Test message",
                severity="medium"
            )
    
    def test_empty_source_ip_validation(self):
        """Test validation fails for empty source_ip."""
        with pytest.raises(ValueError, match="source_ip cannot be empty"):
            IRCAlert(
                alert_type="new_host",
                timestamp=datetime.now(),
                source_ip="",
                message="Test message",
                severity="medium"
            )
    
    def test_invalid_ip_address_validation(self):
        """Test validation fails for invalid IP address."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            IRCAlert(
                alert_type="new_host",
                timestamp=datetime.now(),
                source_ip="invalid_ip",
                message="Test message",
                severity="medium"
            )
    
    def test_empty_message_validation(self):
        """Test validation fails for empty message."""
        with pytest.raises(ValueError, match="message cannot be empty"):
            IRCAlert(
                alert_type="new_host",
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                message="",
                severity="medium"
            )
    
    def test_invalid_severity_validation(self):
        """Test validation fails for invalid severity."""
        with pytest.raises(ValueError, match="Invalid severity"):
            IRCAlert(
                alert_type="new_host",
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                message="Test message",
                severity="invalid_severity"
            )
    
    def test_valid_ipv6_address(self):
        """Test validation passes for valid IPv6 address."""
        alert = IRCAlert(
            alert_type="new_host",
            timestamp=datetime.now(),
            source_ip="2001:db8::1",
            message="Test message",
            severity="medium"
        )
        assert alert.source_ip == "2001:db8::1"
    
    def test_mark_as_sent(self):
        """Test marking alert as sent."""
        alert = IRCAlert(
            alert_type="new_host",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            message="Test message",
            severity="medium"
        )
        
        assert alert.sent is False
        alert.mark_as_sent()
        assert alert.sent is True
    
    def test_mark_as_unsent(self):
        """Test marking alert as unsent."""
        alert = IRCAlert(
            alert_type="new_host",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            message="Test message",
            severity="medium",
            sent=True
        )
        
        assert alert.sent is True
        alert.mark_as_unsent()
        assert alert.sent is False
    
    def test_is_high_priority(self):
        """Test checking if alert is high priority."""
        low_alert = IRCAlert("new_host", datetime.now(), "192.168.1.100", "Test", "low")
        medium_alert = IRCAlert("new_host", datetime.now(), "192.168.1.100", "Test", "medium")
        high_alert = IRCAlert("high_threat", datetime.now(), "192.168.1.100", "Test", "high")
        critical_alert = IRCAlert("high_threat", datetime.now(), "192.168.1.100", "Test", "critical")
        
        assert low_alert.is_high_priority() is False
        assert medium_alert.is_high_priority() is False
        assert high_alert.is_high_priority() is True
        assert critical_alert.is_high_priority() is True
    
    def test_get_severity_score(self):
        """Test getting numeric severity score."""
        low_alert = IRCAlert("new_host", datetime.now(), "192.168.1.100", "Test", "low")
        medium_alert = IRCAlert("new_host", datetime.now(), "192.168.1.100", "Test", "medium")
        high_alert = IRCAlert("high_threat", datetime.now(), "192.168.1.100", "Test", "high")
        critical_alert = IRCAlert("high_threat", datetime.now(), "192.168.1.100", "Test", "critical")
        
        assert low_alert.get_severity_score() == 1
        assert medium_alert.get_severity_score() == 2
        assert high_alert.get_severity_score() == 3
        assert critical_alert.get_severity_score() == 4
    
    def test_format_for_irc(self):
        """Test formatting alert for IRC display."""
        timestamp = datetime(2023, 1, 1, 12, 30, 45)
        alert = IRCAlert(
            alert_type="high_threat",
            timestamp=timestamp,
            source_ip="192.168.1.100",
            message="Malware detected",
            severity="critical"
        )
        
        formatted = alert.format_for_irc()
        
        # Check that it contains expected components
        assert "[12:30:45]" in formatted
        assert "CRITICAL" in formatted
        assert "high_threat" in formatted
        assert "192.168.1.100" in formatted
        assert "Malware detected" in formatted
        # Check for IRC color codes
        assert "\x03" in formatted  # Color codes present
    
    def test_get_age_seconds(self):
        """Test getting alert age in seconds."""
        # Create alert 30 seconds ago
        past_time = datetime.now() - timedelta(seconds=30)
        alert = IRCAlert(
            alert_type="new_host",
            timestamp=past_time,
            source_ip="192.168.1.100",
            message="Test message",
            severity="medium"
        )
        
        age = alert.get_age_seconds()
        # Should be approximately 30 seconds (allow some tolerance)
        assert 29 <= age <= 31
    
    def test_is_recent(self):
        """Test checking if alert is recent."""
        # Recent alert (10 seconds ago)
        recent_time = datetime.now() - timedelta(seconds=10)
        recent_alert = IRCAlert(
            alert_type="new_host",
            timestamp=recent_time,
            source_ip="192.168.1.100",
            message="Test message",
            severity="medium"
        )
        
        # Old alert (10 minutes ago)
        old_time = datetime.now() - timedelta(minutes=10)
        old_alert = IRCAlert(
            alert_type="new_host",
            timestamp=old_time,
            source_ip="192.168.1.100",
            message="Test message",
            severity="medium"
        )
        
        assert recent_alert.is_recent() is True
        assert old_alert.is_recent() is False
        
        # Test with custom max age
        assert old_alert.is_recent(max_age_seconds=3600) is True  # 1 hour
    
    def test_to_dict_serialization(self):
        """Test converting IRC alert to dictionary."""
        timestamp = datetime(2023, 1, 1, 12, 0, 0)
        alert = IRCAlert(
            alert_type="high_threat",
            timestamp=timestamp,
            source_ip="192.168.1.100",
            message="Threat detected",
            severity="high",
            sent=True
        )
        
        expected_dict = {
            'alert_type': 'high_threat',
            'timestamp': '2023-01-01T12:00:00',
            'source_ip': '192.168.1.100',
            'message': 'Threat detected',
            'severity': 'high',
            'sent': True
        }
        
        assert alert.to_dict() == expected_dict
    
    def test_from_dict_deserialization(self):
        """Test creating IRC alert from dictionary."""
        data = {
            'alert_type': 'high_threat',
            'timestamp': '2023-01-01T12:00:00',
            'source_ip': '192.168.1.100',
            'message': 'Threat detected',
            'severity': 'high',
            'sent': True
        }
        
        alert = IRCAlert.from_dict(data)
        
        assert alert.alert_type == 'high_threat'
        assert alert.timestamp == datetime(2023, 1, 1, 12, 0, 0)
        assert alert.source_ip == '192.168.1.100'
        assert alert.message == 'Threat detected'
        assert alert.severity == 'high'
        assert alert.sent is True
    
    def test_json_serialization_roundtrip(self):
        """Test JSON serialization and deserialization."""
        original_alert = IRCAlert(
            alert_type="interesting_traffic",
            timestamp=datetime(2023, 1, 1, 12, 0, 0),
            source_ip="10.0.0.1",
            message="Unusual activity pattern",
            severity="medium",
            sent=False
        )
        
        # Serialize to JSON and back
        json_str = original_alert.to_json()
        restored_alert = IRCAlert.from_json(json_str)
        
        # Compare all fields
        assert restored_alert.alert_type == original_alert.alert_type
        assert restored_alert.timestamp == original_alert.timestamp
        assert restored_alert.source_ip == original_alert.source_ip
        assert restored_alert.message == original_alert.message
        assert restored_alert.severity == original_alert.severity
        assert restored_alert.sent == original_alert.sent
    
    def test_create_new_host_alert_factory(self):
        """Test creating new host alert using factory method."""
        first_seen = datetime(2023, 1, 1, 12, 0, 0)
        alert = IRCAlert.create_new_host_alert("192.168.1.100", first_seen)
        
        assert alert.alert_type == "new_host"
        assert alert.timestamp == first_seen
        assert alert.source_ip == "192.168.1.100"
        assert "New host detected: 192.168.1.100" in alert.message
        assert alert.severity == "medium"
        assert alert.sent is False
    
    def test_create_threat_alert_factory(self):
        """Test creating threat alert using factory method."""
        alert = IRCAlert.create_threat_alert(
            "10.0.0.1", 
            "Malware execution detected", 
            "critical"
        )
        
        assert alert.alert_type == "high_threat"
        assert alert.source_ip == "10.0.0.1"
        assert alert.message == "Malware execution detected"
        assert alert.severity == "critical"
        assert alert.sent is False
        # Timestamp should be recent
        assert (datetime.now() - alert.timestamp).total_seconds() < 5
    
    def test_create_interesting_traffic_alert_factory(self):
        """Test creating interesting traffic alert using factory method."""
        alert = IRCAlert.create_interesting_traffic_alert(
            "172.16.0.1",
            "Unusual port scanning pattern"
        )
        
        assert alert.alert_type == "interesting_traffic"
        assert alert.source_ip == "172.16.0.1"
        assert alert.message == "Unusual port scanning pattern"
        assert alert.severity == "low"
        assert alert.sent is False
        # Timestamp should be recent
        assert (datetime.now() - alert.timestamp).total_seconds() < 5