"""
LogMonitor service for real-time log file monitoring.
"""

import os
import time
import threading
from pathlib import Path
from typing import List, Callable, Optional, Dict, Any
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from ..interfaces.monitor_interface import MonitorInterface
from ..interfaces.log_parser_interface import LogParserInterface
from ..models.log_entry import LogEntry


class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log file changes."""
    
    def __init__(self, log_monitor: 'LogMonitor'):
        """Initialize the handler.
        
        Args:
            log_monitor: Reference to the LogMonitor instance
        """
        super().__init__()
        self.log_monitor = log_monitor
    
    def on_modified(self, event):
        """Handle file modification events.
        
        Args:
            event: File system event
        """
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            print(f"DEBUG: File modified event: {event.src_path}")  # Debug output
            # Check if this is our monitored log file
            if event.src_path == self.log_monitor.log_path:
                print(f"DEBUG: Matched our log file, handling change")  # Debug output
                self.log_monitor._handle_file_change()
            else:
                print(f"DEBUG: Not our log file (expected: {self.log_monitor.log_path})")  # Debug output


class LogMonitor(MonitorInterface):
    """
    Real-time log file monitor using watchdog library.
    
    Features:
    - Real-time file monitoring with watchdog
    - Callback system for new log entries
    - File rotation handling and reconnection
    - Buffering for performance
    - Thread-safe operations
    """
    
    def __init__(self, parser: Optional[LogParserInterface] = None, buffer_size: int = 1000, batch_size: int = 100):
        """Initialize the log monitor.
        
        Args:
            parser: Log parser instance to use for parsing entries
            buffer_size: Maximum number of entries to keep in memory buffer
            batch_size: Number of lines to process in each batch for performance
        """
        self.parser = parser
        self.log_path: Optional[str] = None
        self.observer: Optional[Observer] = None
        self.file_handler: Optional[LogFileHandler] = None
        self.callbacks: List[Callable[[LogEntry], None]] = []
        self.buffer_size = buffer_size
        self.batch_size = batch_size
        self.recent_entries: deque[LogEntry] = deque(maxlen=buffer_size)
        self.is_monitoring = False
        self._lock = threading.Lock()
        self._file_position = 0
        self._file_handle: Optional[Any] = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._reconnect_delay = 1.0  # seconds
        self._pending_lines: List[str] = []  # Buffer for batching
        self._parse_errors: List[str] = []  # Track parsing errors
    
    def start_monitoring(self, log_path: str) -> None:
        """Start monitoring a log file.
        
        Args:
            log_path: Path to the log file to monitor
            
        Raises:
            FileNotFoundError: If log file doesn't exist
            PermissionError: If no read permission for log file
            RuntimeError: If already monitoring or setup fails
        """
        print(f"DEBUG: Starting log monitoring for: {log_path}")  # Debug output
        
        if self.is_monitoring:
            print("DEBUG: Already monitoring, raising error")  # Debug output
            raise RuntimeError("Already monitoring a log file. Stop current monitoring first.")
        
        # Validate log file
        if not os.path.exists(log_path):
            print(f"DEBUG: Log file not found: {log_path}")  # Debug output
            raise FileNotFoundError(f"Log file not found: {log_path}")
        
        if not os.access(log_path, os.R_OK):
            print(f"DEBUG: No read permission for: {log_path}")  # Debug output
            raise PermissionError(f"No read permission for log file: {log_path}")
        
        self.log_path = os.path.abspath(log_path)
        print(f"DEBUG: Log path set to: {self.log_path}")  # Debug output
        
        try:
            # Set up file monitoring
            print("DEBUG: Setting up file monitoring...")  # Debug output
            self._setup_file_monitoring()
            
            # Read existing content to get current position
            print("DEBUG: Initializing file position...")  # Debug output
            self._initialize_file_position()
            print(f"DEBUG: File position initialized to: {self._file_position}")  # Debug output
            
            # Start the observer
            print("DEBUG: Starting file observer...")  # Debug output
            self.observer.start()
            self.is_monitoring = True
            self._reconnect_attempts = 0
            print("DEBUG: Log monitoring started successfully!")  # Debug output
            
        except Exception as e:
            print(f"DEBUG: Error starting monitoring: {str(e)}")  # Debug output
            self._cleanup()
            raise RuntimeError(f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring the log file."""
        with self._lock:
            if not self.is_monitoring:
                return
            
            self.is_monitoring = False
            self._cleanup()
    
    def get_recent_entries(self, count: int) -> List[LogEntry]:
        """Get recent log entries.
        
        Args:
            count: Number of recent entries to retrieve
            
        Returns:
            List of recent LogEntry objects (up to count items)
        """
        with self._lock:
            # Convert deque to list and return last 'count' items
            entries = list(self.recent_entries)
            return entries[-count:] if count < len(entries) else entries
    
    def register_callback(self, callback: Callable[[LogEntry], None]) -> None:
        """Register a callback for new log entries.
        
        Args:
            callback: Function to call when new entries are detected.
                     Should accept a LogEntry parameter.
        """
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[LogEntry], None]) -> None:
        """Unregister a callback.
        
        Args:
            callback: Function to remove from callbacks
        """
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def clear_callbacks(self) -> None:
        """Clear all registered callbacks."""
        self.callbacks.clear()
    
    def set_parser(self, parser: LogParserInterface) -> None:
        """Set the log parser to use for parsing entries.
        
        Args:
            parser: Log parser instance
        """
        self.parser = parser
    
    def get_parser(self) -> Optional[LogParserInterface]:
        """Get the current log parser.
        
        Returns:
            Current parser instance or None
        """
        return self.parser
    
    def get_buffer_size(self) -> int:
        """Get current buffer size."""
        return self.buffer_size
    
    def get_batch_size(self) -> int:
        """Get current batch size."""
        return self.batch_size
    
    def set_batch_size(self, size: int) -> None:
        """Set batch size for processing lines.
        
        Args:
            size: New batch size (must be positive)
        """
        if size <= 0:
            raise ValueError("Batch size must be positive")
        self.batch_size = size
    
    def set_buffer_size(self, size: int) -> None:
        """Set buffer size for recent entries.
        
        Args:
            size: New buffer size (must be positive)
        """
        if size <= 0:
            raise ValueError("Buffer size must be positive")
        
        with self._lock:
            self.buffer_size = size
            # Create new deque with new size and preserve existing entries
            old_entries = list(self.recent_entries)
            self.recent_entries = deque(old_entries[-size:], maxlen=size)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status information.
        
        Returns:
            Dictionary with status information
        """
        return {
            'is_monitoring': self.is_monitoring,
            'log_path': self.log_path,
            'buffer_size': self.buffer_size,
            'entries_in_buffer': len(self.recent_entries),
            'callbacks_registered': len(self.callbacks),
            'file_position': self._file_position,
            'reconnect_attempts': self._reconnect_attempts,
            'batch_size': self.batch_size,
            'pending_lines': len(self._pending_lines),
            'parse_errors': len(self._parse_errors),
            'has_parser': self.parser is not None
        }
    
    def _setup_file_monitoring(self) -> None:
        """Set up watchdog file monitoring."""
        if not self.log_path:
            raise RuntimeError("No log path specified")
        
        # Create observer and handler
        self.observer = Observer()
        self.file_handler = LogFileHandler(self)
        
        # Watch the directory containing the log file
        log_dir = os.path.dirname(self.log_path)
        self.observer.schedule(self.file_handler, log_dir, recursive=False)
    
    def _initialize_file_position(self) -> None:
        """Initialize file position to end of file for new content monitoring."""
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to end to get file size
                f.seek(0, 2)  # Seek to end
                self._file_position = f.tell()
        except IOError as e:
            raise RuntimeError(f"Failed to initialize file position: {str(e)}")
    
    def _handle_file_change(self) -> None:
        """Handle file change events - read new content and process."""
        print("DEBUG: File change detected!")  # Debug output
        
        if not self.is_monitoring or not self.log_path:
            print("DEBUG: Not monitoring or no log path, ignoring change")  # Debug output
            return
        
        try:
            self._read_new_content()
            self._reconnect_attempts = 0  # Reset on successful read
        except Exception as e:
            print(f"DEBUG: Error handling file change: {str(e)}")  # Debug output
            self._handle_read_error(e)
    
    def _read_new_content(self) -> None:
        """Read new content from the log file."""
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to our last position
                f.seek(self._file_position)
                
                # Read new lines
                new_lines = []
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        new_lines.append(line)
                
                # Update file position
                self._file_position = f.tell()
                
                # Process new lines
                if new_lines:
                    self._process_new_lines(new_lines)
                    
        except IOError as e:
            # File might have been rotated or temporarily unavailable
            self._handle_file_rotation_or_error(e)
    
    def _process_new_lines(self, lines: List[str]) -> None:
        """Process new log lines with batching and parsing.
        
        Args:
            lines: List of new log lines to process
        """
        # Add lines to pending buffer
        self._pending_lines.extend(lines)
        
        # Process in batches for performance
        while len(self._pending_lines) >= self.batch_size:
            batch = self._pending_lines[:self.batch_size]
            self._pending_lines = self._pending_lines[self.batch_size:]
            self._process_batch(batch)
        
        # If we have remaining lines and no more are expected soon, process them
        # This happens during shutdown or when file changes are infrequent
        if self._pending_lines and not self.is_monitoring:
            self._process_batch(self._pending_lines)
            self._pending_lines.clear()
    
    def _process_batch(self, lines: List[str]) -> None:
        """Process a batch of log lines.
        
        Args:
            lines: Batch of log lines to process
        """
        entries = []
        
        for line in lines:
            entry = self._parse_line(line)
            if entry:
                entries.append(entry)
        
        # Add entries to buffer in batch
        if entries:
            with self._lock:
                self.recent_entries.extend(entries)
            
            # Notify callbacks for each entry
            for entry in entries:
                self._notify_callbacks(entry)
    
    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line using the configured parser.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            Parsed LogEntry or None if parsing fails
        """
        if not line.strip():
            return None
        
        # If no parser is configured, create a basic entry
        if not self.parser:
            from datetime import datetime
            return LogEntry(
                timestamp=datetime.now(),
                session_id="unknown",
                event_type="system",
                source_ip="0.0.0.0",
                message=line.strip()
            )
        
        # Use the parser to parse the line
        try:
            entry = self.parser.parse_entry_safe(line.strip())
            if entry is None:
                # Parser failed but didn't raise exception
                self._parse_errors.append(f"Failed to parse: {line.strip()}")
                print(f"DEBUG: Failed to parse line: {line.strip()}")  # Debug output
                # Create fallback entry
                from datetime import datetime
                entry = LogEntry(
                    timestamp=datetime.now(),
                    session_id="unknown",
                    event_type="system",
                    source_ip="0.0.0.0",
                    message=line.strip()
                )
            else:
                print(f"DEBUG: Successfully parsed: {entry.event_type} from {entry.source_ip}")  # Debug output
            return entry
        except Exception as e:
            # Parser raised an exception
            self._parse_errors.append(f"Parse error for '{line.strip()}': {str(e)}")
            print(f"DEBUG: Parse exception: {str(e)} for line: {line.strip()}")  # Debug output
            # Create fallback entry
            from datetime import datetime
            return LogEntry(
                timestamp=datetime.now(),
                session_id="unknown",
                event_type="error",
                source_ip="0.0.0.0",
                message=line.strip()
            )
    
    def _notify_callbacks(self, entry: LogEntry) -> None:
        """Notify all registered callbacks of a new entry.
        
        Args:
            entry: New LogEntry to send to callbacks
        """
        print(f"DEBUG: Notifying {len(self.callbacks)} callbacks for entry: {entry.event_type}")  # Debug output
        for callback in self.callbacks:
            try:
                callback(entry)
                print(f"DEBUG: Callback executed successfully")  # Debug output
            except Exception as e:
                # Log callback errors but don't stop processing
                # In a real implementation, we'd use proper logging
                print(f"Callback error: {str(e)}")
    
    def _handle_file_rotation_or_error(self, error: Exception) -> None:
        """Handle file rotation or read errors.
        
        Args:
            error: The exception that occurred
        """
        # Check if file still exists
        if not os.path.exists(self.log_path):
            # File might have been rotated
            self._attempt_reconnection()
        else:
            # File exists but we can't read it - might be temporary
            self._handle_read_error(error)
    
    def _handle_read_error(self, error: Exception) -> None:
        """Handle read errors with retry logic.
        
        Args:
            error: The exception that occurred
        """
        self._reconnect_attempts += 1
        
        if self._reconnect_attempts <= self._max_reconnect_attempts:
            # Wait before retrying
            time.sleep(self._reconnect_delay * self._reconnect_attempts)
            
            # Try to re-initialize file position
            try:
                self._initialize_file_position()
            except Exception:
                # If we can't re-initialize, we'll try again on next file change
                pass
        else:
            # Too many failures - stop monitoring
            print(f"Too many read errors, stopping monitoring: {str(error)}")
            self.stop_monitoring()
    
    def _attempt_reconnection(self) -> None:
        """Attempt to reconnect to a rotated log file."""
        self._reconnect_attempts += 1
        
        if self._reconnect_attempts <= self._max_reconnect_attempts:
            # Wait for file to potentially reappear
            time.sleep(self._reconnect_delay * self._reconnect_attempts)
            
            # Check if file exists now
            if os.path.exists(self.log_path):
                try:
                    # Re-initialize file position (start from end of file to avoid re-reading)
                    self._initialize_file_position()  # This sets position to end of file
                    self._reconnect_attempts = 0  # Reset on success
                except Exception as e:
                    print(f"Reconnection failed: {str(e)}")
        else:
            # Too many reconnection attempts
            print("Too many reconnection attempts, stopping monitoring")
            self.stop_monitoring()
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5.0)  # Wait up to 5 seconds
            except Exception:
                pass  # Ignore cleanup errors
            finally:
                self.observer = None
        
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            finally:
                self._file_handle = None
        
        self.file_handler = None
        self.log_path = None
        self._file_position = 0
        self._reconnect_attempts = 0
        
        # Process any remaining pending lines before cleanup
        if self._pending_lines:
            self._process_batch(self._pending_lines)
            self._pending_lines.clear()
    
    def get_parse_errors(self) -> List[str]:
        """Get list of parsing errors encountered.
        
        Returns:
            List of error messages
        """
        return self._parse_errors.copy()
    
    def clear_parse_errors(self) -> None:
        """Clear the list of parsing errors."""
        self._parse_errors.clear()
    
    def flush_pending_lines(self) -> None:
        """Force processing of any pending lines in the buffer."""
        if self._pending_lines:
            self._process_batch(self._pending_lines)
            self._pending_lines.clear()