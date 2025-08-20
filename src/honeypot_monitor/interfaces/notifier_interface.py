"""
Abstract interface for notification systems.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from ..models.threat_assessment import ThreatAssessment


class NotifierInterface(ABC):
    """Abstract base class for notification systems."""
    
    @abstractmethod
    def connect(self, **kwargs) -> None:
        """Connect to the notification service.
        
        Args:
            **kwargs: Connection parameters specific to the notifier
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the notification service."""
        pass
    
    @abstractmethod
    def send_alert(self, alert_type: str, message: str) -> None:
        """Send a generic alert message.
        
        Args:
            alert_type: Type of alert
            message: Alert message content
        """
        pass
    
    @abstractmethod
    def send_new_host_alert(self, ip: str, first_seen: datetime) -> None:
        """Send alert for new host detection.
        
        Args:
            ip: IP address of the new host
            first_seen: Timestamp when first detected
        """
        pass
    
    @abstractmethod
    def send_threat_alert(self, threat: ThreatAssessment, source_ip: str) -> None:
        """Send alert for threat detection.
        
        Args:
            threat: ThreatAssessment object
            source_ip: Source IP address
        """
        pass
    
    @abstractmethod
    def send_interesting_traffic_alert(self, activity: str, details: str) -> None:
        """Send alert for interesting traffic patterns.
        
        Args:
            activity: Description of the activity
            details: Additional details about the traffic
        """
        pass