"""
Tests for the log viewer TUI component.
"""

import pytest
from datetime import datetime, timedelta
from textual.app import App
from textual.widgets import DataTable, Input, Button, Select

from src.honeypot_monitor.tui.log_viewer import LogViewer, LogDetailView
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.session import Session


class TestApp(App):
    """Test app for mounting widgets."""
    
    def compose(self):
        yield LogViewer()


class TestLogViewer:
    """Test cases for the LogViewer widget."""
    
    @pytest.fixture
    def sample_log_entries(self):
        """Create sample log entries for testing."""
        base_time = datetime.now() - timedelta(hours=1)
        entries = []
        
        for i in range(10):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i * 5),
                session_id=f"sess_{i // 3}",
                event_type="command" if i % 2 == 0 else "login",
                source_ip=f"192.168.1.{100 + i}",
                message=f"Test message {i}",
                command=f"test_command_{i}" if i % 2 == 0 else None,
                threat_level="high" if i % 4 == 0 else "low"
            )
            entries.append(entry)
        
        return entries
    
    @pytest.fixture
    def log_viewer(self):
        """Create a LogViewer instance for testing."""
        return LogViewer()
    
    def test_log_viewer_initialization(self, log_viewer):
        """Test that LogViewer initializes correctly."""
        assert log_viewer.current_page == 1
        assert log_viewer.page_size == 50
        assert log_viewer.total_entries == 0
        assert log_viewer.search_term == ""
        assert log_viewer.ip_filter == ""
        assert log_viewer.event_filter == ""
        assert log_viewer.date_filter == ""
        assert not log_viewer.show_detail_panel
        assert log_viewer.log_entries == []
        assert log_viewer.filtered_entries == []
        assert log_viewer.selected_entry is None
    
    def test_set_data_source(self, log_viewer, sample_log_entries):
        """Test setting a data source for the log viewer."""
        def data_source():
            return sample_log_entries
        
        # Test without mounting (just check the data source is set)
        log_viewer.data_source = data_source
        assert log_viewer.data_source == data_source
    
    def test_apply_search_filter(self, log_viewer, sample_log_entries):
        """Test search filtering functionality."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.search_term = "Test message 5"
        log_viewer._apply_filters()
        
        assert len(log_viewer.filtered_entries) == 1
        assert log_viewer.filtered_entries[0].message == "Test message 5"
    
    def test_apply_ip_filter(self, log_viewer, sample_log_entries):
        """Test IP address filtering functionality."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.ip_filter = "192.168.1.102"
        log_viewer._apply_filters()
        
        assert len(log_viewer.filtered_entries) == 1
        assert log_viewer.filtered_entries[0].source_ip == "192.168.1.102"
    
    def test_apply_event_type_filter(self, log_viewer, sample_log_entries):
        """Test event type filtering functionality."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.event_filter = "command"
        log_viewer._apply_filters()
        
        # Should have 5 command entries (even indices)
        assert len(log_viewer.filtered_entries) == 5
        for entry in log_viewer.filtered_entries:
            assert entry.event_type == "command"
    
    def test_apply_date_filter(self, log_viewer, sample_log_entries):
        """Test date filtering functionality."""
        log_viewer.log_entries = sample_log_entries
        today = datetime.now().strftime("%Y-%m-%d")
        log_viewer.date_filter = today
        log_viewer._apply_filters()
        
        # All sample entries should be from today
        assert len(log_viewer.filtered_entries) == len(sample_log_entries)
    
    def test_apply_multiple_filters(self, log_viewer, sample_log_entries):
        """Test applying multiple filters simultaneously."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.search_term = "Test"
        log_viewer.event_filter = "command"
        log_viewer._apply_filters()
        
        # Should have command entries that contain "Test"
        assert len(log_viewer.filtered_entries) == 5
        for entry in log_viewer.filtered_entries:
            assert entry.event_type == "command"
            assert "Test" in entry.message
    
    def test_pagination_calculation(self, log_viewer, sample_log_entries):
        """Test pagination calculations."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.filtered_entries = sample_log_entries
        log_viewer.page_size = 3
        
        # Should have 4 pages for 10 entries with page size 3
        total_pages = (len(log_viewer.filtered_entries) + log_viewer.page_size - 1) // log_viewer.page_size
        assert total_pages == 4
        
        # Test page 1 entries
        log_viewer.current_page = 1
        start_idx = (log_viewer.current_page - 1) * log_viewer.page_size
        end_idx = start_idx + log_viewer.page_size
        page_entries = log_viewer.filtered_entries[start_idx:end_idx]
        assert len(page_entries) == 3
        
        # Test last page entries
        log_viewer.current_page = 4
        start_idx = (log_viewer.current_page - 1) * log_viewer.page_size
        end_idx = start_idx + log_viewer.page_size
        page_entries = log_viewer.filtered_entries[start_idx:end_idx]
        assert len(page_entries) == 1  # Only 1 entry on last page
    
    def test_clear_filters(self, log_viewer, sample_log_entries):
        """Test clearing all filters."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.search_term = "test"
        log_viewer.ip_filter = "192.168.1.100"
        log_viewer.event_filter = "command"
        log_viewer.date_filter = "2023-01-01"
        
        # Test clearing filters without UI interaction
        log_viewer.search_term = ""
        log_viewer.ip_filter = ""
        log_viewer.event_filter = ""
        log_viewer.date_filter = ""
        
        assert log_viewer.search_term == ""
        assert log_viewer.ip_filter == ""
        assert log_viewer.event_filter == ""
        assert log_viewer.date_filter == ""
    
    def test_page_navigation(self, log_viewer, sample_log_entries):
        """Test page navigation functionality."""
        log_viewer.log_entries = sample_log_entries
        log_viewer.filtered_entries = sample_log_entries
        log_viewer.page_size = 3
        log_viewer.current_page = 1
        
        # Test next page logic
        total_pages = max(1, (len(log_viewer.filtered_entries) + log_viewer.page_size - 1) // log_viewer.page_size)
        if log_viewer.current_page < total_pages:
            log_viewer.current_page += 1
        assert log_viewer.current_page == 2
        
        # Test previous page logic
        if log_viewer.current_page > 1:
            log_viewer.current_page -= 1
        assert log_viewer.current_page == 1
        
        # Test can't go below page 1
        if log_viewer.current_page > 1:
            log_viewer.current_page -= 1
        assert log_viewer.current_page == 1
        
        # Test can't go beyond last page
        log_viewer.current_page = 4  # Last page for 10 entries with page size 3
        if log_viewer.current_page < total_pages:
            log_viewer.current_page += 1
        assert log_viewer.current_page == 4


class TestLogDetailView:
    """Test cases for the LogDetailView widget."""
    
    @pytest.fixture
    def sample_log_entry(self):
        """Create a sample log entry for testing."""
        return LogEntry(
            timestamp=datetime.now(),
            session_id="sess_123",
            event_type="command",
            source_ip="192.168.1.100",
            message="Test command execution",
            command="ls -la /tmp",
            file_path="/tmp/test.txt",
            threat_level="medium"
        )
    
    @pytest.fixture
    def log_detail_view(self, sample_log_entry):
        """Create a LogDetailView instance for testing."""
        return LogDetailView(sample_log_entry)
    
    def test_log_detail_view_initialization(self, log_detail_view, sample_log_entry):
        """Test that LogDetailView initializes correctly."""
        assert log_detail_view.log_entry == sample_log_entry
        assert log_detail_view.related_sessions == []
    
    def test_format_entry_details(self, log_detail_view, sample_log_entry):
        """Test formatting of log entry details."""
        details = log_detail_view._format_entry_details()
        
        assert sample_log_entry.session_id in details
        assert sample_log_entry.source_ip in details
        assert sample_log_entry.event_type in details
        assert sample_log_entry.message in details
        assert sample_log_entry.command in details
        assert sample_log_entry.file_path in details
        assert sample_log_entry.threat_level in details


class TestLogViewerIntegration:
    """Integration tests for log viewer functionality."""
    
    def test_log_viewer_with_real_data_flow(self):
        """Test log viewer with a realistic data flow."""
        # Create sample data
        entries = []
        base_time = datetime.now() - timedelta(hours=2)
        
        for i in range(100):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                session_id=f"sess_{i // 10}",
                event_type="command" if i % 3 == 0 else "login",
                source_ip=f"10.0.0.{i % 20 + 1}",
                message=f"Activity {i}: {'Command execution' if i % 3 == 0 else 'Login attempt'}",
                command=f"cmd_{i}" if i % 3 == 0 else None,
                threat_level="high" if i % 10 == 0 else "low"
            )
            entries.append(entry)
        
        # Create log viewer and set data
        log_viewer = LogViewer()
        log_viewer.log_entries = entries
        log_viewer.filtered_entries = entries
        log_viewer.total_entries = len(entries)
        
        # Test filtering
        log_viewer.search_term = "Command"
        log_viewer._apply_filters()
        
        # Should have entries containing "Command"
        assert len(log_viewer.filtered_entries) > 0
        for entry in log_viewer.filtered_entries:
            assert "Command" in entry.message
        
        # Test pagination with filtered results
        log_viewer.page_size = 10
        log_viewer.current_page = 1
        
        start_idx = (log_viewer.current_page - 1) * log_viewer.page_size
        end_idx = start_idx + log_viewer.page_size
        page_entries = log_viewer.filtered_entries[start_idx:end_idx]
        
        assert len(page_entries) <= 10
        
        # Test threat level filtering
        log_viewer.search_term = ""
        log_viewer._apply_filters()
        
        high_threat_entries = [e for e in log_viewer.filtered_entries if e.threat_level == "high"]
        assert len(high_threat_entries) == 10  # Every 10th entry has high threat
    
    def test_export_functionality_preparation(self):
        """Test preparation for export functionality (task 9.2)."""
        # Create sample data for export testing
        entries = []
        base_time = datetime.now()
        
        for i in range(5):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                session_id=f"sess_{i}",
                event_type="command",
                source_ip=f"192.168.1.{100 + i}",
                message=f"Export test entry {i}",
                command=f"test_cmd_{i}",
                threat_level="medium"
            )
            entries.append(entry)
        
        # Test data conversion to dict (needed for CSV/JSON export)
        for entry in entries:
            entry_dict = entry.to_dict()
            assert "timestamp" in entry_dict
            assert "session_id" in entry_dict
            assert "event_type" in entry_dict
            assert "source_ip" in entry_dict
            assert "message" in entry_dict
            
        # Test JSON serialization
        for entry in entries:
            json_str = entry.to_json()
            assert isinstance(json_str, str)
            assert entry.session_id in json_str
    
    def test_csv_export_functionality(self):
        """Test CSV export functionality."""
        # Create sample data
        entries = []
        base_time = datetime.now()
        
        for i in range(3):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                session_id=f"sess_{i}",
                event_type="command",
                source_ip=f"192.168.1.{100 + i}",
                message=f"Test entry {i}",
                command=f"cmd_{i}",
                threat_level="low"
            )
            entries.append(entry)
        
        # Create log viewer and test CSV export
        log_viewer = LogViewer()
        csv_output = log_viewer._export_to_csv(entries)
        
        # Verify CSV structure
        lines = csv_output.strip().split('\n')
        assert len(lines) == 4  # Header + 3 data rows
        
        # Check header
        header = lines[0]
        assert "Timestamp" in header
        assert "Session ID" in header
        assert "Event Type" in header
        assert "Source IP" in header
        
        # Check data rows
        for i, line in enumerate(lines[1:]):
            assert f"sess_{i}" in line
            assert f"192.168.1.{100 + i}" in line
            assert "command" in line
    
    def test_json_export_functionality(self):
        """Test JSON export functionality."""
        # Create sample data
        entries = []
        base_time = datetime.now()
        
        for i in range(2):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                session_id=f"sess_{i}",
                event_type="login",
                source_ip=f"10.0.0.{i + 1}",
                message=f"Login attempt {i}",
                threat_level="medium"
            )
            entries.append(entry)
        
        # Create log viewer and test JSON export
        log_viewer = LogViewer()
        json_output = log_viewer._export_to_json(entries)
        
        # Parse and verify JSON structure
        import json
        data = json.loads(json_output)
        
        assert "export_timestamp" in data
        assert "total_entries" in data
        assert "entries" in data
        assert data["total_entries"] == 2
        assert len(data["entries"]) == 2
        
        # Check entry structure
        for i, entry_data in enumerate(data["entries"]):
            assert entry_data["session_id"] == f"sess_{i}"
            assert entry_data["event_type"] == "login"
            assert entry_data["source_ip"] == f"10.0.0.{i + 1}"
    
    def test_session_correlation_functionality(self):
        """Test session correlation functionality."""
        # Create sample data with multiple entries per session
        entries = []
        base_time = datetime.now()
        
        # Session 1: Multiple commands
        for i in range(3):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                session_id="sess_1",
                event_type="command",
                source_ip="192.168.1.100",
                message=f"Command {i}",
                command=f"ls -la /tmp/{i}",
                threat_level="low"
            )
            entries.append(entry)
        
        # Session 2: Login and file access
        entry = LogEntry(
            timestamp=base_time + timedelta(minutes=5),
            session_id="sess_2",
            event_type="login",
            source_ip="10.0.0.5",
            message="Login attempt",
            threat_level="medium"
        )
        entries.append(entry)
        
        entry = LogEntry(
            timestamp=base_time + timedelta(minutes=6),
            session_id="sess_2",
            event_type="file_access",
            source_ip="10.0.0.5",
            message="File access",
            file_path="/etc/passwd",
            threat_level="high"
        )
        entries.append(entry)
        
        # Create log viewer and test session correlation
        log_viewer = LogViewer()
        log_viewer.filtered_entries = entries
        sessions = log_viewer._correlate_sessions()
        
        # Verify session correlation
        assert len(sessions) == 2
        assert "sess_1" in sessions
        assert "sess_2" in sessions
        
        # Check session 1
        session1 = sessions["sess_1"]
        assert session1.source_ip == "192.168.1.100"
        assert session1.command_count() == 3
        assert session1.threat_score > 0  # Should have some threat score
        
        # Check session 2
        session2 = sessions["sess_2"]
        assert session2.source_ip == "10.0.0.5"
        assert session2.file_access_count() == 1
        assert session2.threat_score > session1.threat_score  # Higher due to high threat entry
    
    def test_statistics_calculation(self):
        """Test statistics calculation functionality."""
        # Create diverse sample data
        entries = []
        base_time = datetime.now() - timedelta(hours=2)
        
        event_types = ["login", "command", "file_access", "connection"]
        threat_levels = ["low", "medium", "high"]
        ips = ["192.168.1.100", "10.0.0.5", "172.16.0.1"]
        
        for i in range(20):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i * 3),
                session_id=f"sess_{i // 5}",
                event_type=event_types[i % len(event_types)],
                source_ip=ips[i % len(ips)],
                message=f"Activity {i}",
                command=f"cmd_{i}" if i % 4 == 0 else None,
                threat_level=threat_levels[i % len(threat_levels)] if i % 3 == 0 else None
            )
            entries.append(entry)
        
        # Create log viewer and calculate statistics
        log_viewer = LogViewer()
        log_viewer.filtered_entries = entries
        stats = log_viewer._calculate_statistics()
        
        # Verify statistics
        assert stats["total_entries"] == 20
        assert stats["unique_ips"] == 3
        assert len(stats["event_types"]) == 4
        assert "login" in stats["event_types"]
        assert "command" in stats["event_types"]
        
        # Check that we have some threat level data
        if stats["threat_levels"]:
            assert isinstance(stats["threat_levels"], dict)
        
        # Check session analysis
        assert stats["total_sessions"] == 4  # 20 entries / 5 per session
        
        # Check time-based analysis
        assert "hourly_activity" in stats
        assert isinstance(stats["hourly_activity"], dict)