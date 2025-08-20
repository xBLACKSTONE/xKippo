"""
LogEntry data model for honeypot monitoring.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
import ipaddress
import json


@dataclass
class LogEntry:
    """
    Represents a single log entry from the honeypot.
    
    Attributes:
        timestamp: When the event occurred
        session_id: Unique identifier for the session
        event_type: Type of event (login, command, file_access, etc.)
        source_ip: IP address of the connection source
        message: Raw log message
        command: Executed command (if applicable)
        file_path: File path accessed (if applicable)
        threat_level: Assessed threat level (low, medium, high, critical)
    """
    timestamp: datetime
    session_id: str
    event_type: str
    source_ip: str
    message: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    threat_level: Optional[str] = None
    
    def __post_init__(self):
        """Validate data after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate the log entry data for integrity.
        
        Raises:
            ValueError: If validation fails
        """
        # Validate required fields
        if not self.session_id or not self.session_id.strip():
            raise ValueError("session_id cannot be empty")
        
        if not self.event_type or not self.event_type.strip():
            raise ValueError("event_type cannot be empty")
        
        if not self.source_ip or not self.source_ip.strip():
            raise ValueError("source_ip cannot be empty")
        
        if not self.message or not self.message.strip():
            raise ValueError("message cannot be empty")
        
        # Validate IP address format
        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {self.source_ip}")
        
        # Validate event_type
        valid_event_types = {
            'login', 'logout', 'command', 'file_access', 'connection', 
            'disconnect', 'authentication', 'error', 'system'
        }
        if self.event_type not in valid_event_types:
            raise ValueError(f"Invalid event_type: {self.event_type}. Must be one of {valid_event_types}")
        
        # Validate threat_level if provided
        if self.threat_level is not None:
            valid_threat_levels = {'low', 'medium', 'high', 'critical'}
            if self.threat_level not in valid_threat_levels:
                raise ValueError(f"Invalid threat_level: {self.threat_level}. Must be one of {valid_threat_levels}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the log entry to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the log entry
        """
        return {
            'timestamp': self.timestamp.isoformat(),
            'session_id': self.session_id,
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'message': self.message,
            'command': self.command,
            'file_path': self.file_path,
            'threat_level': self.threat_level
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """
        Create a LogEntry from a dictionary.
        
        Args:
            data: Dictionary containing log entry data
            
        Returns:
            LogEntry instance
        """
        # Parse timestamp if it's a string
        timestamp = data['timestamp']
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        return cls(
            timestamp=timestamp,
            session_id=data['session_id'],
            event_type=data['event_type'],
            source_ip=data['source_ip'],
            message=data['message'],
            command=data.get('command'),
            file_path=data.get('file_path'),
            threat_level=data.get('threat_level')
        )
    
    def to_json(self) -> str:
        """
        Convert the log entry to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'LogEntry':
        """
        Create a LogEntry from JSON string.
        
        Args:
            json_str: JSON string containing log entry data
            
        Returns:
            LogEntry instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)