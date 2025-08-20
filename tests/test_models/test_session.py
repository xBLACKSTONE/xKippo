"""
Unit tests for Session model.
"""

import pytest
from datetime import datetime, timedelta
from src.honeypot_monitor.models.session import Session


class TestSession:
    """Test cases for Session model."""
    
    def test_valid_session_creation(self):
        """Test creating a valid session."""
        start_time = datetime.now()
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=start_time
        )
        
        assert session.session_id == "session_123"
        assert session.source_ip == "192.168.1.100"
        assert session.start_time == start_time
        assert session.end_time is None
        assert session.commands == []
        assert session.files_accessed == []
        assert session.threat_score == 0.0
    
    def test_session_with_all_fields(self):
        """Test creating a session with all fields."""
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=30)
        
        session = Session(
            session_id="session_456",
            source_ip="10.0.0.1",
            start_time=start_time,
            end_time=end_time,
            commands=["ls", "whoami"],
            files_accessed=["/etc/passwd", "/home/user"],
            threat_score=0.7
        )
        
        assert session.end_time == end_time
        assert session.commands == ["ls", "whoami"]
        assert session.files_accessed == ["/etc/passwd", "/home/user"]
        assert session.threat_score == 0.7
    
    def test_empty_session_id_validation(self):
        """Test validation fails for empty session_id."""
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            Session(
                session_id="",
                source_ip="192.168.1.100",
                start_time=datetime.now()
            )
    
    def test_empty_source_ip_validation(self):
        """Test validation fails for empty source_ip."""
        with pytest.raises(ValueError, match="source_ip cannot be empty"):
            Session(
                session_id="session_123",
                source_ip="",
                start_time=datetime.now()
            )
    
    def test_invalid_ip_address_validation(self):
        """Test validation fails for invalid IP address."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            Session(
                session_id="session_123",
                source_ip="invalid_ip",
                start_time=datetime.now()
            )
    
    def test_invalid_threat_score_validation(self):
        """Test validation fails for invalid threat_score."""
        with pytest.raises(ValueError, match="threat_score must be between 0.0 and 1.0"):
            Session(
                session_id="session_123",
                source_ip="192.168.1.100",
                start_time=datetime.now(),
                threat_score=1.5
            )
        
        with pytest.raises(ValueError, match="threat_score must be between 0.0 and 1.0"):
            Session(
                session_id="session_123",
                source_ip="192.168.1.100",
                start_time=datetime.now(),
                threat_score=-0.1
            )
    
    def test_invalid_time_consistency_validation(self):
        """Test validation fails when end_time is before start_time."""
        start_time = datetime.now()
        end_time = start_time - timedelta(minutes=10)
        
        with pytest.raises(ValueError, match="end_time cannot be before start_time"):
            Session(
                session_id="session_123",
                source_ip="192.168.1.100",
                start_time=start_time,
                end_time=end_time
            )
    
    def test_add_command(self):
        """Test adding commands to session."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        session.add_command("ls -la")
        session.add_command("whoami")
        session.add_command("")  # Should be ignored
        session.add_command("   pwd   ")  # Should be trimmed
        
        assert session.commands == ["ls -la", "whoami", "pwd"]
    
    def test_add_file_access(self):
        """Test adding file accesses to session."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        session.add_file_access("/etc/passwd")
        session.add_file_access("/home/user")
        session.add_file_access("/etc/passwd")  # Duplicate, should not be added again
        session.add_file_access("")  # Should be ignored
        session.add_file_access("   /tmp/test   ")  # Should be trimmed
        
        assert session.files_accessed == ["/etc/passwd", "/home/user", "/tmp/test"]
    
    def test_update_threat_score(self):
        """Test updating threat score."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        session.update_threat_score(0.5)
        assert session.threat_score == 0.5
        
        session.update_threat_score(1.0)
        assert session.threat_score == 1.0
        
        with pytest.raises(ValueError, match="threat_score must be between 0.0 and 1.0"):
            session.update_threat_score(1.1)
    
    def test_end_session(self):
        """Test ending a session."""
        start_time = datetime.now()
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=start_time
        )
        
        # Test ending with specific time
        end_time = start_time + timedelta(minutes=30)
        session.end_session(end_time)
        assert session.end_time == end_time
        
        # Test ending with invalid time
        with pytest.raises(ValueError, match="end_time cannot be before start_time"):
            session.end_session(start_time - timedelta(minutes=10))
    
    def test_end_session_default_time(self):
        """Test ending a session with default time (now)."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        before_end = datetime.now()
        session.end_session()
        after_end = datetime.now()
        
        assert session.end_time is not None
        assert before_end <= session.end_time <= after_end
    
    def test_is_active(self):
        """Test checking if session is active."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        assert session.is_active() is True
        
        session.end_session()
        assert session.is_active() is False
    
    def test_duration(self):
        """Test calculating session duration."""
        start_time = datetime.now()
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=start_time
        )
        
        # Active session should return None
        assert session.duration() is None
        
        # Ended session should return duration in seconds
        end_time = start_time + timedelta(minutes=30)
        session.end_session(end_time)
        assert session.duration() == 1800.0  # 30 minutes = 1800 seconds
    
    def test_command_count(self):
        """Test getting command count."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        assert session.command_count() == 0
        
        session.add_command("ls")
        session.add_command("whoami")
        assert session.command_count() == 2
    
    def test_file_access_count(self):
        """Test getting file access count."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now()
        )
        
        assert session.file_access_count() == 0
        
        session.add_file_access("/etc/passwd")
        session.add_file_access("/home/user")
        assert session.file_access_count() == 2
    
    def test_to_dict_serialization(self):
        """Test converting session to dictionary."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime(2023, 1, 1, 12, 30, 0)
        
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=start_time,
            end_time=end_time,
            commands=["ls", "whoami"],
            files_accessed=["/etc/passwd"],
            threat_score=0.5
        )
        
        expected_dict = {
            'session_id': 'session_123',
            'source_ip': '192.168.1.100',
            'start_time': '2023-01-01T12:00:00',
            'end_time': '2023-01-01T12:30:00',
            'commands': ['ls', 'whoami'],
            'files_accessed': ['/etc/passwd'],
            'threat_score': 0.5
        }
        
        assert session.to_dict() == expected_dict
    
    def test_from_dict_deserialization(self):
        """Test creating session from dictionary."""
        data = {
            'session_id': 'session_123',
            'source_ip': '192.168.1.100',
            'start_time': '2023-01-01T12:00:00',
            'end_time': '2023-01-01T12:30:00',
            'commands': ['ls', 'whoami'],
            'files_accessed': ['/etc/passwd'],
            'threat_score': 0.5
        }
        
        session = Session.from_dict(data)
        
        assert session.session_id == 'session_123'
        assert session.source_ip == '192.168.1.100'
        assert session.start_time == datetime(2023, 1, 1, 12, 0, 0)
        assert session.end_time == datetime(2023, 1, 1, 12, 30, 0)
        assert session.commands == ['ls', 'whoami']
        assert session.files_accessed == ['/etc/passwd']
        assert session.threat_score == 0.5
    
    def test_json_serialization_roundtrip(self):
        """Test JSON serialization and deserialization."""
        original_session = Session(
            session_id="session_123",
            source_ip="10.0.0.1",
            start_time=datetime(2023, 1, 1, 12, 0, 0),
            commands=["ls", "whoami"],
            files_accessed=["/etc/passwd", "/home/user"],
            threat_score=0.7
        )
        
        # Serialize to JSON and back
        json_str = original_session.to_json()
        restored_session = Session.from_json(json_str)
        
        # Compare all fields
        assert restored_session.session_id == original_session.session_id
        assert restored_session.source_ip == original_session.source_ip
        assert restored_session.start_time == original_session.start_time
        assert restored_session.end_time == original_session.end_time
        assert restored_session.commands == original_session.commands
        assert restored_session.files_accessed == original_session.files_accessed
        assert restored_session.threat_score == original_session.threat_score