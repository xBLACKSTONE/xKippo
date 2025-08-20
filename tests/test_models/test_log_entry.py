"""
Unit tests for LogEntry model.
"""

import pytest
from datetime import datetime
from src.honeypot_monitor.models.log_entry import LogEntry


class TestLogEntry:
    """Test cases for LogEntry model."""
    
    def test_valid_log_entry_creation(self):
        """Test creating a valid log entry."""
        timestamp = datetime.now()
        entry = LogEntry(
            timestamp=timestamp,
            session_id="session_123",
            event_type="login",
            source_ip="192.168.1.100",
            message="User login attempt"
        )
        
        assert entry.timestamp == timestamp
        assert entry.session_id == "session_123"
        assert entry.event_type == "login"
        assert entry.source_ip == "192.168.1.100"
        assert entry.message == "User login attempt"
        assert entry.command is None
        assert entry.file_path is None
        assert entry.threat_level is None
    
    def test_log_entry_with_optional_fields(self):
        """Test creating a log entry with optional fields."""
        timestamp = datetime.now()
        entry = LogEntry(
            timestamp=timestamp,
            session_id="session_456",
            event_type="command",
            source_ip="10.0.0.1",
            message="Command executed",
            command="ls -la",
            file_path="/home/user",
            threat_level="medium"
        )
        
        assert entry.command == "ls -la"
        assert entry.file_path == "/home/user"
        assert entry.threat_level == "medium"
    
    def test_empty_session_id_validation(self):
        """Test validation fails for empty session_id."""
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="",
                event_type="login",
                source_ip="192.168.1.100",
                message="Test message"
            )
    
    def test_empty_event_type_validation(self):
        """Test validation fails for empty event_type."""
        with pytest.raises(ValueError, match="event_type cannot be empty"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="",
                source_ip="192.168.1.100",
                message="Test message"
            )
    
    def test_empty_source_ip_validation(self):
        """Test validation fails for empty source_ip."""
        with pytest.raises(ValueError, match="source_ip cannot be empty"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="login",
                source_ip="",
                message="Test message"
            )
    
    def test_empty_message_validation(self):
        """Test validation fails for empty message."""
        with pytest.raises(ValueError, match="message cannot be empty"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="login",
                source_ip="192.168.1.100",
                message=""
            )
    
    def test_invalid_ip_address_validation(self):
        """Test validation fails for invalid IP address."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="login",
                source_ip="invalid_ip",
                message="Test message"
            )
    
    def test_invalid_event_type_validation(self):
        """Test validation fails for invalid event_type."""
        with pytest.raises(ValueError, match="Invalid event_type"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="invalid_type",
                source_ip="192.168.1.100",
                message="Test message"
            )
    
    def test_invalid_threat_level_validation(self):
        """Test validation fails for invalid threat_level."""
        with pytest.raises(ValueError, match="Invalid threat_level"):
            LogEntry(
                timestamp=datetime.now(),
                session_id="session_123",
                event_type="login",
                source_ip="192.168.1.100",
                message="Test message",
                threat_level="invalid_level"
            )
    
    def test_valid_ipv6_address(self):
        """Test validation passes for valid IPv6 address."""
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="login",
            source_ip="2001:db8::1",
            message="Test message"
        )
        assert entry.source_ip == "2001:db8::1"
    
    def test_to_dict_serialization(self):
        """Test converting log entry to dictionary."""
        timestamp = datetime(2023, 1, 1, 12, 0, 0)
        entry = LogEntry(
            timestamp=timestamp,
            session_id="session_123",
            event_type="command",
            source_ip="192.168.1.100",
            message="Test command",
            command="whoami",
            threat_level="low"
        )
        
        expected_dict = {
            'timestamp': '2023-01-01T12:00:00',
            'session_id': 'session_123',
            'event_type': 'command',
            'source_ip': '192.168.1.100',
            'message': 'Test command',
            'command': 'whoami',
            'file_path': None,
            'threat_level': 'low'
        }
        
        assert entry.to_dict() == expected_dict
    
    def test_from_dict_deserialization(self):
        """Test creating log entry from dictionary."""
        data = {
            'timestamp': '2023-01-01T12:00:00',
            'session_id': 'session_123',
            'event_type': 'command',
            'source_ip': '192.168.1.100',
            'message': 'Test command',
            'command': 'whoami',
            'threat_level': 'low'
        }
        
        entry = LogEntry.from_dict(data)
        
        assert entry.timestamp == datetime(2023, 1, 1, 12, 0, 0)
        assert entry.session_id == 'session_123'
        assert entry.event_type == 'command'
        assert entry.source_ip == '192.168.1.100'
        assert entry.message == 'Test command'
        assert entry.command == 'whoami'
        assert entry.threat_level == 'low'
    
    def test_json_serialization_roundtrip(self):
        """Test JSON serialization and deserialization."""
        original_entry = LogEntry(
            timestamp=datetime(2023, 1, 1, 12, 0, 0),
            session_id="session_123",
            event_type="file_access",
            source_ip="10.0.0.1",
            message="File accessed",
            file_path="/etc/passwd",
            threat_level="high"
        )
        
        # Serialize to JSON and back
        json_str = original_entry.to_json()
        restored_entry = LogEntry.from_json(json_str)
        
        # Compare all fields
        assert restored_entry.timestamp == original_entry.timestamp
        assert restored_entry.session_id == original_entry.session_id
        assert restored_entry.event_type == original_entry.event_type
        assert restored_entry.source_ip == original_entry.source_ip
        assert restored_entry.message == original_entry.message
        assert restored_entry.file_path == original_entry.file_path
        assert restored_entry.threat_level == original_entry.threat_level