"""
KippoLogParser service for parsing Kippo honeypot log files.
"""

import re
import os
from datetime import datetime
from typing import List, Optional, Dict, Pattern, Set, Tuple
from ..interfaces.log_parser_interface import LogParserInterface
from ..models.log_entry import LogEntry
from ..models.session import Session


class ParseError(Exception):
    """Exception raised when log parsing fails."""
    pass


class SessionCorrelator:
    """Helper class for correlating log entries into sessions."""
    
    def __init__(self):
        """Initialize the session correlator."""
        self._sessions: Dict[str, Session] = {}
        self._ip_to_sessions: Dict[str, Set[str]] = {}
    
    def add_entry(self, entry: LogEntry) -> Optional[Session]:
        """
        Add a log entry and update session correlation.
        
        Args:
            entry: LogEntry to add to session tracking
            
        Returns:
            Updated Session object if session exists, None otherwise
        """
        session_id = entry.session_id
        source_ip = entry.source_ip
        
        # Initialize IP tracking if needed
        if source_ip not in self._ip_to_sessions:
            self._ip_to_sessions[source_ip] = set()
        
        # Create or update session
        if session_id not in self._sessions:
            self._sessions[session_id] = Session(
                session_id=session_id,
                source_ip=source_ip,
                start_time=entry.timestamp,
                end_time=None,
                commands=[],
                files_accessed=[],
                threat_score=0.0
            )
            self._ip_to_sessions[source_ip].add(session_id)
        
        session = self._sessions[session_id]
        
        # Update session based on entry type
        if entry.event_type == 'command' and entry.command:
            session.commands.append(entry.command)
        elif entry.event_type == 'file_access' and entry.file_path:
            session.files_accessed.append(entry.file_path)
        elif entry.event_type == 'logout':
            session.end_time = entry.timestamp
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        return self._sessions.get(session_id)
    
    def get_sessions_by_ip(self, source_ip: str) -> List[Session]:
        """Get all sessions for a given IP address."""
        session_ids = self._ip_to_sessions.get(source_ip, set())
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]
    
    def get_all_sessions(self) -> List[Session]:
        """Get all tracked sessions."""
        return list(self._sessions.values())


class KippoLogParser(LogParserInterface):
    """
    Parser for Kippo honeypot log files.
    
    Supports standard Kippo log formats including:
    - Connection events
    - Authentication attempts
    - Command execution
    - File operations
    - Session management
    
    Advanced features:
    - Command extraction and analysis
    - File path parsing and validation
    - Session correlation and tracking
    - Error handling and recovery
    """
    
    def __init__(self):
        """Initialize the parser with regex patterns for different log types."""
        self._patterns = self._compile_patterns()
        self._supported_formats = ['kippo_default', 'kippo_json', 'kippo_syslog']
        self._session_correlator = SessionCorrelator()
        self._parse_errors: List[Tuple[str, str]] = []  # (line, error_message)
        self._command_extractors = self._compile_command_extractors()
        self._file_path_patterns = self._compile_file_path_patterns()
    
    def _compile_patterns(self) -> Dict[str, Pattern]:
        """
        Compile regex patterns for different Kippo log entry types.
        
        Returns:
            Dictionary of compiled regex patterns
        """
        patterns = {}
        
        # More flexible base pattern that can handle various timestamp formats or malformed ones
        base_pattern = r'(?P<timestamp>[^\[]*?) \[(?P<service>[^\]]+)\] '
        
        # Connection established
        patterns['connection'] = re.compile(
            base_pattern + r'connection from (?P<source_ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)'
        )
        
        # Authentication attempts
        patterns['auth_success'] = re.compile(
            base_pattern + r'login attempt \[(?P<username>[^\]]+)/(?P<password>[^\]]+)\] succeeded'
        )
        
        patterns['auth_failure'] = re.compile(
            base_pattern + r'login attempt \[(?P<username>[^\]]+)/(?P<password>[^\]]+)\] failed'
        )
        
        # Command execution
        patterns['command'] = re.compile(
            base_pattern + r'CMD: (?P<command>.*)'
        )
        
        # File operations
        patterns['file_download'] = re.compile(
            base_pattern + r'file download: (?P<file_path>.*)'
        )
        
        patterns['file_upload'] = re.compile(
            base_pattern + r'file upload: (?P<file_path>.*)'
        )
        
        # Session events
        patterns['session_start'] = re.compile(
            base_pattern + r'New connection: (?P<source_ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+) \((?P<session_id>[^)]+)\)'
        )
        
        patterns['session_end'] = re.compile(
            base_pattern + r'Connection lost: (?P<source_ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+) \((?P<session_id>[^)]+)\)'
        )
        
        # Generic pattern for unmatched lines
        patterns['generic'] = re.compile(
            base_pattern + r'(?P<message>.*)'
        )
        
        return patterns
    
    def parse_entry(self, raw_line: str) -> LogEntry:
        """
        Parse a single log entry from raw text.
        
        Args:
            raw_line: Raw log line text
            
        Returns:
            Parsed LogEntry object
            
        Raises:
            ParseError: If the line cannot be parsed
        """
        if not raw_line or not raw_line.strip():
            raise ParseError("Empty log line")
        
        raw_line = raw_line.strip()
        
        # Try to match against each pattern
        for pattern_name, pattern in self._patterns.items():
            match = pattern.match(raw_line)
            if match:
                return self._create_log_entry(pattern_name, match, raw_line)
        
        # If no pattern matches, raise an error
        raise ParseError(f"Unable to parse log line: {raw_line}")
    
    def _create_log_entry(self, pattern_name: str, match: re.Match, raw_line: str) -> LogEntry:
        """
        Create a LogEntry object from a regex match.
        
        Args:
            pattern_name: Name of the matched pattern
            match: Regex match object
            raw_line: Original raw log line
            
        Returns:
            LogEntry object
        """
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp_str = groups.get('timestamp', '').strip()
        try:
            # Try to parse standard Kippo timestamp format first
            if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4}', timestamp_str):
                # Standard format: 2024-01-15 10:30:45+0000
                clean_timestamp = timestamp_str.split('+')[0].split('-')
                if len(clean_timestamp) >= 3:
                    date_part = '-'.join(clean_timestamp[:3])
                    time_part = timestamp_str.split(' ')[1].split('+')[0].split('-')[0]
                    timestamp_str = f"{date_part} {time_part}"
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                else:
                    raise ValueError("Invalid timestamp format")
            else:
                # For malformed timestamps, use current time
                timestamp = datetime.now()
        except (ValueError, IndexError):
            # Fallback to current time if parsing fails
            timestamp = datetime.now()
        
        # Extract session ID from service field or use a default
        session_id = groups.get('session_id', 'unknown')
        if not session_id or session_id == 'unknown':
            # Try to extract from service field
            service = groups.get('service', '')
            if 'ssh-connection' in service:
                session_id = f"ssh-{hash(raw_line) % 10000}"
            else:
                session_id = f"session-{hash(raw_line) % 10000}"
        
        # Determine event type and extract relevant data
        source_ip = groups.get('source_ip', '0.0.0.0')
        command = None
        file_path = None
        event_type = 'system'  # default
        
        if pattern_name == 'connection':
            event_type = 'connection'
        elif pattern_name in ['auth_success', 'auth_failure']:
            event_type = 'authentication'
        elif pattern_name == 'command':
            event_type = 'command'
            command = groups.get('command', '')
        elif pattern_name in ['file_download', 'file_upload']:
            event_type = 'file_access'
            file_path = groups.get('file_path', '')
        elif pattern_name == 'session_start':
            event_type = 'login'
        elif pattern_name == 'session_end':
            event_type = 'logout'
        else:
            event_type = 'system'
        
        return LogEntry(
            timestamp=timestamp,
            session_id=session_id,
            event_type=event_type,
            source_ip=source_ip,
            message=raw_line,
            command=command,
            file_path=file_path
        )
    
    def validate_format(self, log_path: str) -> bool:
        """
        Validate if the log file format is supported.
        
        Args:
            log_path: Path to the log file
            
        Returns:
            True if format is supported, False otherwise
        """
        if not os.path.exists(log_path):
            return False
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Read first few lines to check format
                for _ in range(10):  # Check up to 10 lines
                    line = f.readline()
                    if not line:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to parse the line
                    try:
                        self.parse_entry(line)
                        return True  # If we can parse at least one line, format is valid
                    except ParseError:
                        continue
                
                return False  # No parseable lines found
                
        except (IOError, UnicodeDecodeError):
            return False
    
    def get_supported_formats(self) -> List[str]:
        """
        Get list of supported log formats.
        
        Returns:
            List of supported format names
        """
        return self._supported_formats.copy()
    
    def _compile_command_extractors(self) -> Dict[str, Pattern]:
        """
        Compile regex patterns for extracting commands and their components.
        
        Returns:
            Dictionary of command extraction patterns
        """
        extractors = {}
        
        # Extract command with arguments
        extractors['full_command'] = re.compile(r'^(?P<command>\S+)(?:\s+(?P<args>.*))?$')
        
        # Extract file paths from common commands
        extractors['file_operations'] = re.compile(
            r'(?:cat|ls|cd|rm|cp|mv|chmod|chown|touch|mkdir|rmdir|find|grep|tail|head|less|more|vi|vim|nano|wget|curl|scp|rsync)\s+(?P<paths>.*)'
        )
        
        # Extract URLs from download commands
        extractors['download_urls'] = re.compile(
            r'(?:wget|curl|fetch)\s+.*?(?P<url>https?://[^\s]+)'
        )
        
        # Extract network commands
        extractors['network_commands'] = re.compile(
            r'(?P<net_cmd>ping|nmap|netstat|ss|telnet|ssh|nc|ncat)\s+(?P<target>.*)'
        )
        
        return extractors
    
    def _compile_file_path_patterns(self) -> Dict[str, Pattern]:
        """
        Compile regex patterns for file path extraction and validation.
        
        Returns:
            Dictionary of file path patterns
        """
        patterns = {}
        
        # Standard Unix file paths
        patterns['unix_path'] = re.compile(r'(?P<path>/[^\s]*)')
        
        # Relative paths
        patterns['relative_path'] = re.compile(r'(?P<path>\.{1,2}/[^\s]*)')
        
        # Home directory paths
        patterns['home_path'] = re.compile(r'(?P<path>~/[^\s]*)')
        
        # Suspicious file extensions
        patterns['suspicious_files'] = re.compile(
            r'(?P<path>[^\s]*\.(?:sh|py|pl|exe|bat|cmd|scr|vbs|js|jar|war|php|asp|jsp))'
        )
        
        return patterns
    
    def extract_command_details(self, command: str) -> Dict[str, Optional[str]]:
        """
        Extract detailed information from a command string.
        
        Args:
            command: Command string to analyze
            
        Returns:
            Dictionary with extracted command details
        """
        if not command:
            return {}
        
        details = {}
        
        # Extract basic command and arguments
        full_match = self._command_extractors['full_command'].match(command)
        if full_match:
            details['base_command'] = full_match.group('command')
            details['arguments'] = full_match.group('args')
        
        # Extract file paths from file operations
        file_match = self._command_extractors['file_operations'].search(command)
        if file_match:
            details['file_paths'] = self._extract_file_paths(file_match.group('paths'))
        
        # Extract URLs from download commands
        url_match = self._command_extractors['download_urls'].search(command)
        if url_match:
            details['download_url'] = url_match.group('url')
        
        # Extract network targets
        net_match = self._command_extractors['network_commands'].search(command)
        if net_match:
            details['network_command'] = net_match.group('net_cmd')
            details['network_target'] = net_match.group('target')
        
        return details
    
    def _extract_file_paths(self, path_string: str) -> List[str]:
        """
        Extract file paths from a string containing multiple paths.
        
        Args:
            path_string: String potentially containing file paths
            
        Returns:
            List of extracted file paths
        """
        if not path_string:
            return []
        
        paths = []
        
        # Try each file path pattern
        for pattern_name, pattern in self._file_path_patterns.items():
            matches = pattern.findall(path_string)
            paths.extend(matches)
        
        # Also split by spaces and check each token
        tokens = path_string.split()
        for token in tokens:
            # Check if token looks like a file path
            if ('/' in token or token.startswith('.') or 
                any(token.endswith(ext) for ext in ['.txt', '.log', '.conf', '.cfg', '.sh', '.py'])):
                if token not in paths:
                    paths.append(token)
        
        return list(set(paths))  # Remove duplicates
    
    def validate_file_path(self, file_path: str) -> Dict[str, bool]:
        """
        Validate and categorize a file path.
        
        Args:
            file_path: File path to validate
            
        Returns:
            Dictionary with validation results
        """
        if not file_path:
            return {'valid': False}
        
        validation = {
            'valid': True,
            'absolute': file_path.startswith('/'),
            'relative': file_path.startswith('./') or file_path.startswith('../'),
            'home_directory': file_path.startswith('~/'),
            'suspicious': False,
            'system_file': False
        }
        
        # Check for suspicious file extensions
        suspicious_match = self._file_path_patterns['suspicious_files'].search(file_path)
        validation['suspicious'] = suspicious_match is not None
        
        # Check for system files
        system_paths = ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/root/', '/home/']
        validation['system_file'] = any(file_path.startswith(path) for path in system_paths)
        
        return validation
    
    def correlate_session(self, entry: LogEntry) -> Optional[Session]:
        """
        Add entry to session correlation and return updated session.
        
        Args:
            entry: LogEntry to correlate
            
        Returns:
            Updated Session object if available
        """
        return self._session_correlator.add_entry(entry)
    
    def get_session_by_id(self, session_id: str) -> Optional[Session]:
        """
        Get session information by session ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session object if found, None otherwise
        """
        return self._session_correlator.get_session(session_id)
    
    def get_sessions_by_ip(self, source_ip: str) -> List[Session]:
        """
        Get all sessions for a given IP address.
        
        Args:
            source_ip: IP address to search for
            
        Returns:
            List of Session objects
        """
        return self._session_correlator.get_sessions_by_ip(source_ip)
    
    def get_parse_errors(self) -> List[Tuple[str, str]]:
        """
        Get list of parsing errors encountered.
        
        Returns:
            List of (line, error_message) tuples
        """
        return self._parse_errors.copy()
    
    def clear_parse_errors(self) -> None:
        """Clear the list of parsing errors."""
        self._parse_errors.clear()
    
    def parse_entry_safe(self, raw_line: str) -> Optional[LogEntry]:
        """
        Parse a log entry with error recovery - doesn't raise exceptions.
        
        Args:
            raw_line: Raw log line text
            
        Returns:
            Parsed LogEntry object or None if parsing fails
        """
        try:
            entry = self.parse_entry(raw_line)
            
            # Enhance entry with command details if it's a command
            if entry.event_type == 'command' and entry.command:
                command_details = self.extract_command_details(entry.command)
                # Store additional details in a way that doesn't break the LogEntry model
                # For now, we'll just validate the command exists
                if command_details:
                    pass  # Could extend LogEntry model to store these details
            
            # Correlate with session
            self.correlate_session(entry)
            
            return entry
            
        except ParseError as e:
            self._parse_errors.append((raw_line, str(e)))
            return None
        except Exception as e:
            self._parse_errors.append((raw_line, f"Unexpected error: {str(e)}"))
            return None
    
    def parse_file_batch(self, file_path: str, max_lines: Optional[int] = None) -> List[LogEntry]:
        """
        Parse a log file in batch mode with error recovery.
        
        Args:
            file_path: Path to the log file
            max_lines: Maximum number of lines to parse (None for all)
            
        Returns:
            List of successfully parsed LogEntry objects
        """
        entries = []
        
        if not os.path.exists(file_path):
            self._parse_errors.append((file_path, "File does not exist"))
            return entries
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                line_count = 0
                for line in f:
                    if max_lines and line_count >= max_lines:
                        break
                    
                    entry = self.parse_entry_safe(line.strip())
                    if entry:
                        entries.append(entry)
                    
                    line_count += 1
                    
        except IOError as e:
            self._parse_errors.append((file_path, f"IO Error: {str(e)}"))
        
        return entries