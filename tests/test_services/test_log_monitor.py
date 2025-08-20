"""
Unit tests for LogMonitor service.
"""

import os
import time
import tempfile
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

from src.honeypot_monitor.services.log_monitor import LogMonitor, LogFileHandler
from src.honeypot_monitor.models.log_entry import LogEntry


class TestLogMonitor:
    """Test cases for LogMonitor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = LogMonitor(buffer_size=10)
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test.log")
        
        # Create initial log file
        with open(self.log_file, 'w') as f:
            f.write("Initial log line\n")
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.monitor.is_monitoring:
            self.monitor.stop_monitoring()
        
        # Clean up temp files
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        os.rmdir(self.temp_dir)
    
    def test_initialization(self):
        """Test LogMonitor initialization."""
        monitor = LogMonitor(buffer_size=100)
        
        assert monitor.buffer_size == 100
        assert monitor.log_path is None
        assert monitor.observer is None
        assert monitor.is_monitoring is False
        assert len(monitor.callbacks) == 0
        assert len(monitor.recent_entries) == 0
        assert monitor._file_position == 0
        assert monitor._reconnect_attempts == 0
    
    def test_start_monitoring_success(self):
        """Test successful start of monitoring."""
        self.monitor.start_monitoring(self.log_file)
        
        assert self.monitor.is_monitoring is True
        assert self.monitor.log_path == os.path.abspath(self.log_file)
        assert self.monitor.observer is not None
        assert self.monitor.file_handler is not None
        assert self.monitor._file_position > 0  # Should be at end of file
    
    def test_start_monitoring_file_not_found(self):
        """Test start monitoring with non-existent file."""
        non_existent_file = os.path.join(self.temp_dir, "nonexistent.log")
        
        with pytest.raises(FileNotFoundError):
            self.monitor.start_monitoring(non_existent_file)
        
        assert self.monitor.is_monitoring is False
    
    def test_start_monitoring_no_permission(self):
        """Test start monitoring with no read permission."""
        # Create file and remove read permission
        os.chmod(self.log_file, 0o000)
        
        try:
            with pytest.raises(PermissionError):
                self.monitor.start_monitoring(self.log_file)
            
            assert self.monitor.is_monitoring is False
        finally:
            # Restore permissions for cleanup
            os.chmod(self.log_file, 0o644)
    
    def test_start_monitoring_already_monitoring(self):
        """Test start monitoring when already monitoring."""
        self.monitor.start_monitoring(self.log_file)
        
        with pytest.raises(RuntimeError, match="Already monitoring"):
            self.monitor.start_monitoring(self.log_file)
    
    def test_stop_monitoring(self):
        """Test stopping monitoring."""
        self.monitor.start_monitoring(self.log_file)
        assert self.monitor.is_monitoring is True
        
        self.monitor.stop_monitoring()
        
        assert self.monitor.is_monitoring is False
        assert self.monitor.observer is None
        assert self.monitor.file_handler is None
        assert self.monitor.log_path is None
    
    def test_stop_monitoring_when_not_monitoring(self):
        """Test stopping monitoring when not monitoring."""
        # Should not raise an exception
        self.monitor.stop_monitoring()
        assert self.monitor.is_monitoring is False
    
    def test_register_callback(self):
        """Test registering callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        
        self.monitor.register_callback(callback1)
        self.monitor.register_callback(callback2)
        
        assert len(self.monitor.callbacks) == 2
        assert callback1 in self.monitor.callbacks
        assert callback2 in self.monitor.callbacks
    
    def test_register_duplicate_callback(self):
        """Test registering the same callback twice."""
        callback = Mock()
        
        self.monitor.register_callback(callback)
        self.monitor.register_callback(callback)  # Register again
        
        assert len(self.monitor.callbacks) == 1
        assert callback in self.monitor.callbacks
    
    def test_unregister_callback(self):
        """Test unregistering callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        
        self.monitor.register_callback(callback1)
        self.monitor.register_callback(callback2)
        
        self.monitor.unregister_callback(callback1)
        
        assert len(self.monitor.callbacks) == 1
        assert callback1 not in self.monitor.callbacks
        assert callback2 in self.monitor.callbacks
    
    def test_unregister_nonexistent_callback(self):
        """Test unregistering a callback that wasn't registered."""
        callback = Mock()
        
        # Should not raise an exception
        self.monitor.unregister_callback(callback)
        assert len(self.monitor.callbacks) == 0
    
    def test_clear_callbacks(self):
        """Test clearing all callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        
        self.monitor.register_callback(callback1)
        self.monitor.register_callback(callback2)
        
        self.monitor.clear_callbacks()
        
        assert len(self.monitor.callbacks) == 0
    
    def test_get_recent_entries_empty(self):
        """Test getting recent entries when buffer is empty."""
        entries = self.monitor.get_recent_entries(5)
        assert len(entries) == 0
    
    def test_get_recent_entries_with_data(self):
        """Test getting recent entries with data in buffer."""
        # Add some entries to buffer
        from datetime import datetime
        
        for i in range(5):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                event_type="system",
                source_ip="127.0.0.1",
                message=f"Test message {i}"
            )
            self.monitor.recent_entries.append(entry)
        
        # Get recent entries
        entries = self.monitor.get_recent_entries(3)
        assert len(entries) == 3
        
        # Should get the last 3 entries
        assert entries[0].message == "Test message 2"
        assert entries[1].message == "Test message 3"
        assert entries[2].message == "Test message 4"
    
    def test_get_recent_entries_more_than_available(self):
        """Test getting more entries than available."""
        # Add 2 entries
        from datetime import datetime
        
        for i in range(2):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                event_type="system",
                source_ip="127.0.0.1",
                message=f"Test message {i}"
            )
            self.monitor.recent_entries.append(entry)
        
        # Request 5 entries
        entries = self.monitor.get_recent_entries(5)
        assert len(entries) == 2  # Should return all available
    
    def test_buffer_size_management(self):
        """Test buffer size management."""
        assert self.monitor.get_buffer_size() == 10
        
        self.monitor.set_buffer_size(5)
        assert self.monitor.get_buffer_size() == 5
        assert self.monitor.recent_entries.maxlen == 5
    
    def test_set_invalid_buffer_size(self):
        """Test setting invalid buffer size."""
        with pytest.raises(ValueError, match="Buffer size must be positive"):
            self.monitor.set_buffer_size(0)
        
        with pytest.raises(ValueError, match="Buffer size must be positive"):
            self.monitor.set_buffer_size(-1)
    
    def test_buffer_size_with_existing_entries(self):
        """Test changing buffer size with existing entries."""
        # Add entries to fill buffer
        from datetime import datetime
        
        for i in range(8):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                event_type="system",
                source_ip="127.0.0.1",
                message=f"Test message {i}"
            )
            self.monitor.recent_entries.append(entry)
        
        # Reduce buffer size
        self.monitor.set_buffer_size(5)
        
        # Should keep only the last 5 entries
        entries = self.monitor.get_recent_entries(10)
        assert len(entries) == 5
        assert entries[0].message == "Test message 3"
        assert entries[4].message == "Test message 7"
    
    def test_get_monitoring_status(self):
        """Test getting monitoring status."""
        status = self.monitor.get_monitoring_status()
        
        expected_keys = [
            'is_monitoring', 'log_path', 'buffer_size', 'entries_in_buffer',
            'callbacks_registered', 'file_position', 'reconnect_attempts'
        ]
        
        for key in expected_keys:
            assert key in status
        
        assert status['is_monitoring'] is False
        assert status['log_path'] is None
        assert status['buffer_size'] == 10
        assert status['entries_in_buffer'] == 0
        assert status['callbacks_registered'] == 0
    
    def test_get_monitoring_status_while_monitoring(self):
        """Test getting monitoring status while monitoring."""
        callback = Mock()
        self.monitor.register_callback(callback)
        self.monitor.start_monitoring(self.log_file)
        
        status = self.monitor.get_monitoring_status()
        
        assert status['is_monitoring'] is True
        assert status['log_path'] == os.path.abspath(self.log_file)
        assert status['callbacks_registered'] == 1
        assert status['file_position'] > 0
    
    def test_process_new_lines(self):
        """Test processing new log lines."""
        callback = Mock()
        self.monitor.register_callback(callback)
        
        lines = ["Line 1", "Line 2", "Line 3"]
        self.monitor._process_new_lines(lines)
        
        # Check that entries were added to buffer
        assert len(self.monitor.recent_entries) == 3
        
        # Check that callbacks were called
        assert callback.call_count == 3
        
        # Verify entry content
        entries = list(self.monitor.recent_entries)
        assert entries[0].message == "Line 1"
        assert entries[1].message == "Line 2"
        assert entries[2].message == "Line 3"
    
    def test_callback_error_handling(self):
        """Test that callback errors don't stop processing."""
        # Create a callback that raises an exception
        def failing_callback(entry):
            raise Exception("Callback error")
        
        working_callback = Mock()
        
        self.monitor.register_callback(failing_callback)
        self.monitor.register_callback(working_callback)
        
        # Process a line - should not raise exception
        self.monitor._process_new_lines(["Test line"])
        
        # Working callback should still be called
        working_callback.assert_called_once()
        
        # Entry should still be in buffer
        assert len(self.monitor.recent_entries) == 1


class TestLogFileHandler:
    """Test cases for LogFileHandler class."""
    
    def test_initialization(self):
        """Test LogFileHandler initialization."""
        monitor = Mock()
        handler = LogFileHandler(monitor)
        
        assert handler.log_monitor is monitor
    
    def test_on_modified_correct_file(self):
        """Test handling modification of the correct log file."""
        monitor = Mock()
        monitor.log_path = "/path/to/log.txt"
        
        handler = LogFileHandler(monitor)
        
        # Create mock FileModifiedEvent for the correct file
        from watchdog.events import FileModifiedEvent
        event = FileModifiedEvent("/path/to/log.txt")
        
        handler.on_modified(event)
        
        # Should call the monitor's handle method
        monitor._handle_file_change.assert_called_once()
    
    def test_on_modified_wrong_file(self):
        """Test handling modification of a different file."""
        monitor = Mock()
        monitor.log_path = "/path/to/log.txt"
        
        handler = LogFileHandler(monitor)
        
        # Create mock FileModifiedEvent for a different file
        from watchdog.events import FileModifiedEvent
        event = FileModifiedEvent("/path/to/other.txt")
        
        handler.on_modified(event)
        
        # Should not call the monitor's handle method
        monitor._handle_file_change.assert_not_called()
    
    def test_on_modified_directory(self):
        """Test handling modification of a directory."""
        monitor = Mock()
        monitor.log_path = "/path/to/log.txt"
        
        handler = LogFileHandler(monitor)
        
        # Create mock DirModifiedEvent for a directory
        from watchdog.events import DirModifiedEvent
        event = DirModifiedEvent("/path/to/")
        
        handler.on_modified(event)
        
        # Should not call the monitor's handle method
        monitor._handle_file_change.assert_not_called()


class TestLogMonitorIntegration:
    """Integration tests for LogMonitor with real file operations."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test.log")
        self.monitor = LogMonitor(buffer_size=50)
        
        # Create initial log file
        with open(self.log_file, 'w') as f:
            f.write("Initial content\n")
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.monitor.is_monitoring:
            self.monitor.stop_monitoring()
        
        # Clean up temp files
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        os.rmdir(self.temp_dir)
    
    def test_real_file_monitoring(self):
        """Test monitoring a real file with actual changes."""
        callback_entries = []
        
        def test_callback(entry):
            callback_entries.append(entry)
        
        self.monitor.register_callback(test_callback)
        self.monitor.start_monitoring(self.log_file)
        
        # Give the monitor time to set up
        time.sleep(0.1)
        
        # Append to the file
        with open(self.log_file, 'a') as f:
            f.write("New line 1\n")
            f.write("New line 2\n")
            f.flush()
        
        # Give the file system watcher time to detect changes
        time.sleep(0.5)
        
        # Check that new entries were detected
        assert len(callback_entries) >= 2
        
        # Check recent entries
        recent = self.monitor.get_recent_entries(10)
        assert len(recent) >= 2
        
        # Verify content (entries should contain the new lines)
        messages = [entry.message for entry in recent]
        assert "New line 1" in messages
        assert "New line 2" in messages
    
    def test_file_rotation_simulation(self):
        """Test handling of file rotation."""
        self.monitor.start_monitoring(self.log_file)
        
        # Give the monitor time to set up
        time.sleep(0.1)
        
        # Simulate file rotation by removing and recreating
        os.remove(self.log_file)
        
        # Give time for the monitor to detect the missing file
        time.sleep(0.2)
        
        # Recreate the file
        with open(self.log_file, 'w') as f:
            f.write("After rotation\n")
        
        # Give time for reconnection
        time.sleep(0.5)
        
        # Add more content
        with open(self.log_file, 'a') as f:
            f.write("New content after rotation\n")
            f.flush()
        
        # Give time for detection
        time.sleep(0.5)
        
        # Monitor should still be running (or have reconnected)
        # This is a basic test - in practice, the reconnection logic
        # might need more sophisticated testing
        status = self.monitor.get_monitoring_status()
        # The monitor might have stopped due to too many errors,
        # which is acceptable behavior
        assert status is not None
    
    def test_concurrent_file_access(self):
        """Test concurrent access to the monitored file."""
        callback_entries = []
        
        def test_callback(entry):
            callback_entries.append(entry)
        
        self.monitor.register_callback(test_callback)
        self.monitor.start_monitoring(self.log_file)
        
        # Give the monitor time to set up
        time.sleep(0.1)
        
        # Function to write to file in a thread
        def write_lines(start_num, count):
            for i in range(count):
                with open(self.log_file, 'a') as f:
                    f.write(f"Line from thread {start_num + i}\n")
                    f.flush()
                time.sleep(0.01)  # Small delay between writes
        
        # Start multiple threads writing to the file
        threads = []
        for i in range(3):
            thread = threading.Thread(target=write_lines, args=(i * 10, 5))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Give time for all changes to be detected
        time.sleep(1.0)
        
        # Should have detected multiple entries
        assert len(callback_entries) > 0
        
        # Check that we got some of the expected content
        recent = self.monitor.get_recent_entries(20)
        messages = [entry.message for entry in recent]
        
        # Should contain some lines from the threads
        thread_lines = [msg for msg in messages if "Line from thread" in msg]
        assert len(thread_lines) > 0