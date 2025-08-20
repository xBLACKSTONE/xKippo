"""
Abstract interface for log monitors.
"""

from abc import ABC, abstractmethod
from typing import List, Callable
from ..models.log_entry import LogEntry


class MonitorInterface(ABC):
    """Abstract base class for log monitors."""
    
    @abstractmethod
    def start_monitoring(self, log_path: str) -> None:
        """Start monitoring a log file.
        
        Args:
            log_path: Path to the log file to monitor
        """
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop monitoring the log file."""
        pass
    
    @abstractmethod
    def get_recent_entries(self, count: int) -> List[LogEntry]:
        """Get recent log entries.
        
        Args:
            count: Number of recent entries to retrieve
            
        Returns:
            List of recent LogEntry objects
        """
        pass
    
    @abstractmethod
    def register_callback(self, callback: Callable[[LogEntry], None]) -> None:
        """Register a callback for new log entries.
        
        Args:
            callback: Function to call when new entries are detected
        """
        pass