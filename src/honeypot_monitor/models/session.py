"""
Session data model for honeypot monitoring.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import ipaddress
import json


@dataclass
class Session:
    """
    Represents a honeypot session with tracking capabilities.
    
    Attributes:
        session_id: Unique identifier for the session
        source_ip: IP address of the connection source
        start_time: When the session started
        end_time: When the session ended (None if still active)
        commands: List of commands executed in this session
        files_accessed: List of file paths accessed during the session
        threat_score: Calculated threat score (0.0 to 1.0)
    """
    session_id: str
    source_ip: str
    start_time: datetime
    end_time: Optional[datetime] = None
    commands: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    
    def __post_init__(self):
        """Validate data after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate the session data for integrity.
        
        Raises:
            ValueError: If validation fails
        """
        # Validate required fields
        if not self.session_id or not self.session_id.strip():
            raise ValueError("session_id cannot be empty")
        
        if not self.source_ip or not self.source_ip.strip():
            raise ValueError("source_ip cannot be empty")
        
        # Validate IP address format
        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {self.source_ip}")
        
        # Validate threat_score range
        if not (0.0 <= self.threat_score <= 1.0):
            raise ValueError(f"threat_score must be between 0.0 and 1.0, got {self.threat_score}")
        
        # Validate time consistency
        if self.end_time is not None and self.end_time < self.start_time:
            raise ValueError("end_time cannot be before start_time")
        
        # Validate lists are not None
        if self.commands is None:
            self.commands = []
        if self.files_accessed is None:
            self.files_accessed = []
    
    def add_command(self, command: str) -> None:
        """
        Add a command to the session's command history.
        
        Args:
            command: Command string to add
        """
        if command and command.strip():
            self.commands.append(command.strip())
    
    def add_file_access(self, file_path: str) -> None:
        """
        Add a file access to the session's file access history.
        
        Args:
            file_path: File path that was accessed
        """
        if file_path and file_path.strip():
            file_path = file_path.strip()
            if file_path not in self.files_accessed:
                self.files_accessed.append(file_path)
    
    def update_threat_score(self, new_score: float) -> None:
        """
        Update the threat score for this session.
        
        Args:
            new_score: New threat score (0.0 to 1.0)
            
        Raises:
            ValueError: If score is out of range
        """
        if not (0.0 <= new_score <= 1.0):
            raise ValueError(f"threat_score must be between 0.0 and 1.0, got {new_score}")
        self.threat_score = new_score
    
    def end_session(self, end_time: Optional[datetime] = None) -> None:
        """
        Mark the session as ended.
        
        Args:
            end_time: When the session ended (defaults to now)
        """
        if end_time is None:
            end_time = datetime.now()
        
        if end_time < self.start_time:
            raise ValueError("end_time cannot be before start_time")
        
        self.end_time = end_time
    
    def is_active(self) -> bool:
        """
        Check if the session is still active.
        
        Returns:
            True if session is active (no end_time), False otherwise
        """
        return self.end_time is None
    
    def duration(self) -> Optional[float]:
        """
        Calculate session duration in seconds.
        
        Returns:
            Duration in seconds, or None if session is still active
        """
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time).total_seconds()
    
    def command_count(self) -> int:
        """
        Get the number of commands executed in this session.
        
        Returns:
            Number of commands
        """
        return len(self.commands)
    
    def file_access_count(self) -> int:
        """
        Get the number of unique files accessed in this session.
        
        Returns:
            Number of unique files accessed
        """
        return len(self.files_accessed)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the session to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the session
        """
        return {
            'session_id': self.session_id,
            'source_ip': self.source_ip,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'commands': self.commands.copy(),
            'files_accessed': self.files_accessed.copy(),
            'threat_score': self.threat_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """
        Create a Session from a dictionary.
        
        Args:
            data: Dictionary containing session data
            
        Returns:
            Session instance
        """
        # Parse timestamps if they're strings
        start_time = data['start_time']
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        
        end_time = data.get('end_time')
        if end_time and isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time)
        
        return cls(
            session_id=data['session_id'],
            source_ip=data['source_ip'],
            start_time=start_time,
            end_time=end_time,
            commands=data.get('commands', []),
            files_accessed=data.get('files_accessed', []),
            threat_score=data.get('threat_score', 0.0)
        )
    
    def to_json(self) -> str:
        """
        Convert the session to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Session':
        """
        Create a Session from JSON string.
        
        Args:
            json_str: JSON string containing session data
            
        Returns:
            Session instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)