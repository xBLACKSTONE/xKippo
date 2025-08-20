"""
IRCAlert data model for honeypot monitoring.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional
import ipaddress
import json


@dataclass
class IRCAlert:
    """
    Represents an IRC alert for honeypot activity.
    
    Attributes:
        alert_type: Type of alert (new_host, high_threat, interesting_traffic)
        timestamp: When the alert was created
        source_ip: IP address that triggered the alert
        message: Alert message content
        severity: Alert severity level (low, medium, high, critical)
        sent: Whether the alert has been sent to IRC
    """
    alert_type: str
    timestamp: datetime
    source_ip: str
    message: str
    severity: str
    sent: bool = False
    
    def __post_init__(self):
        """Validate data after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate the IRC alert data for integrity.
        
        Raises:
            ValueError: If validation fails
        """
        # Validate alert_type
        valid_alert_types = {'new_host', 'high_threat', 'interesting_traffic', 'system_alert', 'connection_alert'}
        if not self.alert_type or self.alert_type not in valid_alert_types:
            raise ValueError(f"Invalid alert_type: {self.alert_type}. Must be one of {valid_alert_types}")
        
        # Validate source_ip
        if not self.source_ip or not self.source_ip.strip():
            raise ValueError("source_ip cannot be empty")
        
        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {self.source_ip}")
        
        # Validate message
        if not self.message or not self.message.strip():
            raise ValueError("message cannot be empty")
        
        # Validate severity
        valid_severities = {'low', 'medium', 'high', 'critical'}
        if not self.severity or self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {valid_severities}")
    
    def mark_as_sent(self) -> None:
        """Mark the alert as sent to IRC."""
        self.sent = True
    
    def mark_as_unsent(self) -> None:
        """Mark the alert as not sent to IRC."""
        self.sent = False
    
    def is_high_priority(self) -> bool:
        """
        Check if this alert is high priority.
        
        Returns:
            True if severity is high or critical, False otherwise
        """
        return self.severity in {'high', 'critical'}
    
    def get_severity_score(self) -> int:
        """
        Get a numeric score for the severity level.
        
        Returns:
            Numeric score (1-4) where higher is more severe
        """
        severity_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_scores.get(self.severity, 0)
    
    def format_for_irc(self) -> str:
        """
        Format the alert message for IRC display.
        
        Returns:
            Formatted IRC message string
        """
        severity_colors = {
            'low': '\x0303',      # Green
            'medium': '\x0308',   # Yellow
            'high': '\x0307',     # Orange
            'critical': '\x0304'  # Red
        }
        
        color_code = severity_colors.get(self.severity, '')
        reset_code = '\x03'
        
        timestamp_str = self.timestamp.strftime('%H:%M:%S')
        
        return f"[{timestamp_str}] {color_code}[{self.severity.upper()}]{reset_code} {self.alert_type}: {self.source_ip} - {self.message}"
    
    def get_age_seconds(self) -> float:
        """
        Get the age of the alert in seconds.
        
        Returns:
            Age in seconds since the alert was created
        """
        return (datetime.now() - self.timestamp).total_seconds()
    
    def is_recent(self, max_age_seconds: int = 300) -> bool:
        """
        Check if the alert is recent (within specified time).
        
        Args:
            max_age_seconds: Maximum age in seconds to consider recent (default: 5 minutes)
            
        Returns:
            True if alert is recent, False otherwise
        """
        return self.get_age_seconds() <= max_age_seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the IRC alert to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the IRC alert
        """
        return {
            'alert_type': self.alert_type,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'message': self.message,
            'severity': self.severity,
            'sent': self.sent
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IRCAlert':
        """
        Create an IRCAlert from a dictionary.
        
        Args:
            data: Dictionary containing IRC alert data
            
        Returns:
            IRCAlert instance
        """
        # Parse timestamp if it's a string
        timestamp = data['timestamp']
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        return cls(
            alert_type=data['alert_type'],
            timestamp=timestamp,
            source_ip=data['source_ip'],
            message=data['message'],
            severity=data['severity'],
            sent=data.get('sent', False)
        )
    
    def to_json(self) -> str:
        """
        Convert the IRC alert to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'IRCAlert':
        """
        Create an IRCAlert from JSON string.
        
        Args:
            json_str: JSON string containing IRC alert data
            
        Returns:
            IRCAlert instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def create_new_host_alert(cls, source_ip: str, first_seen: datetime) -> 'IRCAlert':
        """
        Create a new host alert.
        
        Args:
            source_ip: IP address of the new host
            first_seen: When the host was first seen
            
        Returns:
            IRCAlert for new host
        """
        return cls(
            alert_type='new_host',
            timestamp=first_seen,
            source_ip=source_ip,
            message=f'New host detected: {source_ip}',
            severity='medium'
        )
    
    @classmethod
    def create_threat_alert(cls, source_ip: str, threat_description: str, severity: str = 'high') -> 'IRCAlert':
        """
        Create a threat alert.
        
        Args:
            source_ip: IP address of the threat source
            threat_description: Description of the threat
            severity: Threat severity level
            
        Returns:
            IRCAlert for threat
        """
        return cls(
            alert_type='high_threat',
            timestamp=datetime.now(),
            source_ip=source_ip,
            message=threat_description,
            severity=severity
        )
    
    @classmethod
    def create_interesting_traffic_alert(cls, source_ip: str, activity_description: str) -> 'IRCAlert':
        """
        Create an interesting traffic alert.
        
        Args:
            source_ip: IP address of the traffic source
            activity_description: Description of the interesting activity
            
        Returns:
            IRCAlert for interesting traffic
        """
        return cls(
            alert_type='interesting_traffic',
            timestamp=datetime.now(),
            source_ip=source_ip,
            message=activity_description,
            severity='low'
        )