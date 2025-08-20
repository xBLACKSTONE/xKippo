"""
Abstract interface for log parsers.
"""

from abc import ABC, abstractmethod
from typing import List
from ..models.log_entry import LogEntry


class LogParserInterface(ABC):
    """Abstract base class for log parsers."""
    
    @abstractmethod
    def parse_entry(self, raw_line: str) -> LogEntry:
        """Parse a single log entry from raw text.
        
        Args:
            raw_line: Raw log line text
            
        Returns:
            Parsed LogEntry object
            
        Raises:
            ParseError: If the line cannot be parsed
        """
        pass
    
    @abstractmethod
    def validate_format(self, log_path: str) -> bool:
        """Validate if the log file format is supported.
        
        Args:
            log_path: Path to the log file
            
        Returns:
            True if format is supported, False otherwise
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported log formats.
        
        Returns:
            List of supported format names
        """
        pass