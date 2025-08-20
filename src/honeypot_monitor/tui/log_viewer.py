"""
Log viewer TUI component for displaying and navigating honeypot logs.

This module provides a comprehensive log viewing interface with pagination,
search functionality, filtering capabilities, and detail drill-down views.
"""

from textual.widget import Widget
from textual.widgets import (
    DataTable, Input, Button, Static, Select, Label
)
from textual.containers import (
    Horizontal, Vertical, Container, ScrollableContainer, Grid
)
from textual.binding import Binding
from textual.reactive import reactive, var
from textual.message import Message
from textual.coordinate import Coordinate
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Callable
import re
import csv
import json
import io
from collections import defaultdict, Counter

from ..models.log_entry import LogEntry
from ..models.session import Session


class LogViewer(Widget):
    """
    Log viewer widget with pagination, search, and filtering capabilities.
    
    Features:
    - Paginated log display with configurable page size
    - Search functionality across all log fields
    - Filtering by IP address, date range, and event type
    - Detail drill-down views for individual log entries
    - Keyboard shortcuts for efficient navigation
    """
    
    DEFAULT_CSS = """
    LogViewer {
        layout: vertical;
        height: 100%;
    }
    
    #log-controls {
        layout: horizontal;
        height: 3;
        dock: top;
        background: $surface;
        padding: 0 1;
    }
    
    #search-input {
        width: 30%;
        margin-right: 1;
    }
    
    #ip-filter {
        width: 20%;
        margin-right: 1;
    }
    
    #event-filter {
        width: 15%;
        margin-right: 1;
    }
    
    #date-filter {
        width: 20%;
        margin-right: 1;
    }
    
    #clear-filters {
        width: 10%;
    }
    
    #log-table {
        height: 1fr;
    }
    
    #pagination-controls {
        layout: horizontal;
        height: 3;
        dock: bottom;
        background: $surface;
        padding: 0 1;
    }
    
    #page-info {
        width: 1fr;
        text-align: center;
    }
    
    #detail-panel {
        height: 40%;
        dock: bottom;
        background: $surface;
        border-top: solid $primary;
        padding: 1;
        display: none;
    }
    
    #export-panel {
        height: 60%;
        dock: bottom;
        background: $surface;
        border-top: solid $primary;
        padding: 1;
        display: none;
    }
    
    #session-panel {
        height: 60%;
        dock: bottom;
        background: $surface;
        border-top: solid $primary;
        padding: 1;
        display: none;
    }
    
    #stats-panel {
        height: 60%;
        dock: bottom;
        background: $surface;
        border-top: solid $primary;
        padding: 1;
        display: none;
    }
    
    .filter-active {
        border: solid $warning;
    }
    
    .threat-low {
        color: $success;
    }
    
    .threat-medium {
        color: $warning;
    }
    
    .threat-high {
        color: $error;
    }
    
    .threat-critical {
        color: $error;
        text-style: bold;
    }
    """
    
    BINDINGS = [
        Binding("j", "next_entry", "Next", show=False),
        Binding("k", "prev_entry", "Previous", show=False),
        Binding("n", "next_page", "Next Page"),
        Binding("p", "prev_page", "Prev Page"),
        Binding("enter", "show_details", "Details"),
        Binding("escape", "hide_details", "Hide Details"),
        Binding("f", "focus_search", "Search"),
        Binding("c", "clear_filters", "Clear Filters"),
        Binding("r", "refresh", "Refresh"),
        Binding("e", "show_export", "Export"),
        Binding("s", "show_sessions", "Sessions"),
        Binding("t", "show_stats", "Statistics"),
    ]
    
    # Reactive attributes
    current_page = reactive(1)
    page_size = reactive(50)
    total_entries = reactive(0)
    search_term = reactive("")
    ip_filter = reactive("")
    event_filter = reactive("")
    date_filter = reactive("")
    show_detail_panel = reactive(False)
    
    class LogSelected(Message):
        """Message sent when a log entry is selected."""
        
        def __init__(self, log_entry: LogEntry) -> None:
            self.log_entry = log_entry
            super().__init__()
    
    class FilterChanged(Message):
        """Message sent when filters are changed."""
        
        def __init__(self, filters: Dict[str, str]) -> None:
            self.filters = filters
            super().__init__()
    
    def __init__(self, **kwargs):
        """Initialize the log viewer."""
        super().__init__(**kwargs)
        self.log_entries: List[LogEntry] = []
        self.filtered_entries: List[LogEntry] = []
        self.selected_entry: Optional[LogEntry] = None
        self.data_source: Optional[Callable[[], List[LogEntry]]] = None
        self.sessions: Dict[str, Session] = {}
        self.current_panel: Optional[str] = None
    
    def compose(self):
        """Create the log viewer layout."""
        # Control panel with search and filters
        with Container(id="log-controls"):
            yield Input(placeholder="Search logs...", id="search-input")
            yield Input(placeholder="IP filter", id="ip-filter")
            yield Select(
                [
                    ("All Events", ""),
                    ("Login", "login"),
                    ("Command", "command"),
                    ("File Access", "file_access"),
                    ("Connection", "connection"),
                    ("Authentication", "authentication"),
                    ("Error", "error"),
                ],
                value="",
                id="event-filter"
            )
            yield Input(placeholder="Date (YYYY-MM-DD)", id="date-filter")
            yield Button("Clear", id="clear-filters")
        
        # Main log table
        yield DataTable(id="log-table", zebra_stripes=True, cursor_type="row")
        
        # Pagination controls
        with Container(id="pagination-controls"):
            yield Button("◀ Prev", id="prev-page", disabled=True)
            yield Static("Page 1 of 1", id="page-info")
            yield Button("Next ▶", id="next-page", disabled=True)
        
        # Detail panel (initially hidden)
        with ScrollableContainer(id="detail-panel"):
            yield Static("Select a log entry to view details", id="detail-content")
        
        # Export panel (initially hidden)
        with Container(id="export-panel"):
            with Vertical():
                yield Static("Export Options", classes="panel-header")
                with Horizontal():
                    yield Button("Export CSV", id="export-csv")
                    yield Button("Export JSON", id="export-json")
                    yield Button("Export Filtered", id="export-filtered")
                yield Static("", id="export-status")
                yield Static("", id="export-preview")
        
        # Session correlation panel (initially hidden)
        with Container(id="session-panel"):
            with Vertical():
                yield Static("Session Correlation View", classes="panel-header")
                yield DataTable(id="session-table", zebra_stripes=True)
                yield Static("", id="session-details")
        
        # Statistics panel (initially hidden)
        with Container(id="stats-panel"):
            with Vertical():
                yield Static("Log Statistics", classes="panel-header")
                yield Static("", id="stats-content")
    
    def on_mount(self) -> None:
        """Initialize the log viewer when mounted."""
        self._setup_table()
        self._load_sample_data()
        self._update_display()
    
    def _setup_table(self) -> None:
        """Set up the data table columns."""
        table = self.query_one("#log-table", DataTable)
        table.add_columns(
            "Timestamp",
            "IP Address", 
            "Event Type",
            "Session ID",
            "Threat",
            "Message"
        )
    
    def _load_sample_data(self) -> None:
        """Load sample log data for demonstration."""
        # Generate sample log entries
        base_time = datetime.now() - timedelta(hours=2)
        sample_ips = ["192.168.1.100", "10.0.0.5", "172.16.0.10", "203.0.113.1"]
        event_types = ["login", "command", "file_access", "connection", "authentication"]
        threat_levels = ["low", "medium", "high", "critical"]
        
        self.log_entries = []
        for i in range(200):  # Generate 200 sample entries
            timestamp = base_time + timedelta(minutes=i)
            ip = sample_ips[i % len(sample_ips)]
            event_type = event_types[i % len(event_types)]
            threat = threat_levels[i % len(threat_levels)] if i % 4 == 0 else None
            
            entry = LogEntry(
                timestamp=timestamp,
                session_id=f"sess_{i // 10}",
                event_type=event_type,
                source_ip=ip,
                message=f"Sample {event_type} event from {ip}",
                command=f"ls -la /tmp" if event_type == "command" else None,
                file_path=f"/tmp/file_{i}.txt" if event_type == "file_access" else None,
                threat_level=threat
            )
            self.log_entries.append(entry)
        
        self.total_entries = len(self.log_entries)
        self.filtered_entries = self.log_entries.copy()
    
    def set_data_source(self, data_source: Callable[[], List[LogEntry]]) -> None:
        """
        Set the data source function for loading log entries.
        
        Args:
            data_source: Function that returns a list of LogEntry objects
        """
        self.data_source = data_source
        self.refresh_data()
    
    def refresh_data(self) -> None:
        """Refresh log data from the data source."""
        if self.data_source:
            self.log_entries = self.data_source()
            # Sort entries by timestamp, most recent first
            self.log_entries.sort(key=lambda x: x.timestamp, reverse=True)
            self.total_entries = len(self.log_entries)
            self._apply_filters()
            self._update_display()
    
    def add_log_entry(self, log_entry: LogEntry) -> None:
        """
        Add a new log entry to the viewer in real-time.
        
        Args:
            log_entry: LogEntry to add
        """
        # Add to the beginning of the list for most recent first
        self.log_entries.insert(0, log_entry)
        
        # Limit the number of entries to prevent memory issues
        max_entries = 10000  # Keep last 10k entries
        if len(self.log_entries) > max_entries:
            self.log_entries = self.log_entries[:max_entries]
        
        self.total_entries = len(self.log_entries)
        
        # Reapply filters and update display
        self._apply_filters()
        self._update_display()
    
    def _apply_filters(self) -> None:
        """Apply current filters to the log entries."""
        filtered = self.log_entries.copy()
        
        # Apply search filter
        if self.search_term:
            search_lower = self.search_term.lower()
            filtered = [
                entry for entry in filtered
                if (search_lower in entry.message.lower() or
                    search_lower in entry.source_ip.lower() or
                    search_lower in entry.event_type.lower() or
                    search_lower in entry.session_id.lower() or
                    (entry.command and search_lower in entry.command.lower()) or
                    (entry.file_path and search_lower in entry.file_path.lower()))
            ]
        
        # Apply IP filter
        if self.ip_filter:
            filtered = [
                entry for entry in filtered
                if self.ip_filter in entry.source_ip
            ]
        
        # Apply event type filter
        if self.event_filter:
            filtered = [
                entry for entry in filtered
                if entry.event_type == self.event_filter
            ]
        
        # Apply date filter
        if self.date_filter:
            try:
                filter_date = datetime.strptime(self.date_filter, "%Y-%m-%d").date()
                filtered = [
                    entry for entry in filtered
                    if entry.timestamp.date() == filter_date
                ]
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        # Sort filtered entries by timestamp, most recent first
        filtered.sort(key=lambda x: x.timestamp, reverse=True)
        self.filtered_entries = filtered
        self.current_page = 1  # Reset to first page when filters change
    
    def _update_display(self) -> None:
        """Update the table display with current page data."""
        table = self.query_one("#log-table", DataTable)
        table.clear()
        
        # Calculate pagination
        start_idx = (self.current_page - 1) * self.page_size
        end_idx = start_idx + self.page_size
        page_entries = self.filtered_entries[start_idx:end_idx]
        
        # Add rows to table
        for entry in page_entries:
            threat_class = ""
            if entry.threat_level:
                threat_class = f"threat-{entry.threat_level}"
            
            table.add_row(
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                entry.source_ip,
                entry.event_type,
                entry.session_id,
                entry.threat_level or "-",
                entry.message[:80] + "..." if len(entry.message) > 80 else entry.message,
                key=str(id(entry))
            )
        
        self._update_pagination_controls()
    
    def _update_pagination_controls(self) -> None:
        """Update pagination control states."""
        total_pages = max(1, (len(self.filtered_entries) + self.page_size - 1) // self.page_size)
        
        # Update page info
        page_info = self.query_one("#page-info", Static)
        page_info.update(f"Page {self.current_page} of {total_pages} ({len(self.filtered_entries)} entries)")
        
        # Update button states
        prev_btn = self.query_one("#prev-page", Button)
        next_btn = self.query_one("#next-page", Button)
        
        prev_btn.disabled = self.current_page <= 1
        next_btn.disabled = self.current_page >= total_pages
    
    def _get_selected_entry(self) -> Optional[LogEntry]:
        """Get the currently selected log entry."""
        table = self.query_one("#log-table", DataTable)
        if table.cursor_row >= 0:
            start_idx = (self.current_page - 1) * self.page_size
            entry_idx = start_idx + table.cursor_row
            if entry_idx < len(self.filtered_entries):
                return self.filtered_entries[entry_idx]
        return None
    
    def _show_entry_details(self, entry: LogEntry) -> None:
        """Show detailed information for a log entry."""
        self.selected_entry = entry
        self.show_detail_panel = True
        
        detail_content = self.query_one("#detail-content", Static)
        details = f"""Log Entry Details:

Timestamp: {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Session ID: {entry.session_id}
Event Type: {entry.event_type}
Source IP: {entry.source_ip}
Threat Level: {entry.threat_level or 'None'}

Message: {entry.message}

Command: {entry.command or 'N/A'}
File Path: {entry.file_path or 'N/A'}

Raw Data: {entry.to_json()}"""
        
        detail_content.update(details)
        
        # Show the detail panel
        detail_panel = self.query_one("#detail-panel")
        detail_panel.display = True
    
    def _hide_entry_details(self) -> None:
        """Hide the entry details panel."""
        self.show_detail_panel = False
        detail_panel = self.query_one("#detail-panel")
        detail_panel.display = False
    
    # Event handlers
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input field changes."""
        if event.input.id == "search-input":
            self.search_term = event.value
            self._apply_filters()
            self._update_display()
        elif event.input.id == "ip-filter":
            self.ip_filter = event.value
            self._apply_filters()
            self._update_display()
        elif event.input.id == "date-filter":
            self.date_filter = event.value
            self._apply_filters()
            self._update_display()
    
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle select field changes."""
        if event.select.id == "event-filter":
            self.event_filter = event.value
            self._apply_filters()
            self._update_display()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "prev-page":
            self.action_prev_page()
        elif event.button.id == "next-page":
            self.action_next_page()
        elif event.button.id == "clear-filters":
            self.action_clear_filters()
        elif event.button.id == "export-csv":
            self._handle_export_csv()
        elif event.button.id == "export-json":
            self._handle_export_json()
        elif event.button.id == "export-filtered":
            self._handle_export_filtered()
    
    def _handle_export_csv(self) -> None:
        """Handle CSV export button press."""
        try:
            csv_data = self._export_to_csv(self.filtered_entries)
            filename = f"honeypot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            # In a real implementation, this would save to file
            # For now, just update the status
            status = self.query_one("#export-status", Static)
            status.update(f"CSV export ready: {len(csv_data)} characters, filename: {filename}")
            
        except Exception as e:
            try:
                status = self.query_one("#export-status", Static)
                status.update(f"Export failed: {str(e)}")
            except:
                pass
    
    def _handle_export_json(self) -> None:
        """Handle JSON export button press."""
        try:
            json_data = self._export_to_json(self.filtered_entries)
            filename = f"honeypot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # In a real implementation, this would save to file
            # For now, just update the status
            status = self.query_one("#export-status", Static)
            status.update(f"JSON export ready: {len(json_data)} characters, filename: {filename}")
            
        except Exception as e:
            try:
                status = self.query_one("#export-status", Static)
                status.update(f"Export failed: {str(e)}")
            except:
                pass
    
    def _handle_export_filtered(self) -> None:
        """Handle filtered export button press."""
        try:
            # Export both CSV and JSON of filtered data
            csv_data = self._export_to_csv(self.filtered_entries)
            json_data = self._export_to_json(self.filtered_entries)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            csv_filename = f"honeypot_logs_filtered_{timestamp}.csv"
            json_filename = f"honeypot_logs_filtered_{timestamp}.json"
            
            status = self.query_one("#export-status", Static)
            status.update(f"Filtered export ready: CSV ({len(csv_data)} chars) and JSON ({len(json_data)} chars)")
            
        except Exception as e:
            try:
                status = self.query_one("#export-status", Static)
                status.update(f"Export failed: {str(e)}")
            except:
                pass
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle table row selection."""
        entry = self._get_selected_entry()
        if entry:
            self._show_entry_details(entry)
            self.post_message(self.LogSelected(entry))
    
    # Action methods
    def action_next_page(self) -> None:
        """Go to the next page."""
        total_pages = max(1, (len(self.filtered_entries) + self.page_size - 1) // self.page_size)
        if self.current_page < total_pages:
            self.current_page += 1
            self._update_display()
    
    def action_prev_page(self) -> None:
        """Go to the previous page."""
        if self.current_page > 1:
            self.current_page -= 1
            self._update_display()
    
    def action_next_entry(self) -> None:
        """Move to the next entry in the table."""
        table = self.query_one("#log-table", DataTable)
        if table.cursor_row < table.row_count - 1:
            table.cursor_row += 1
        elif self.current_page < max(1, (len(self.filtered_entries) + self.page_size - 1) // self.page_size):
            self.action_next_page()
            table.cursor_row = 0
    
    def action_prev_entry(self) -> None:
        """Move to the previous entry in the table."""
        table = self.query_one("#log-table", DataTable)
        if table.cursor_row > 0:
            table.cursor_row -= 1
        elif self.current_page > 1:
            self.action_prev_page()
            table.cursor_row = table.row_count - 1
    
    def action_show_details(self) -> None:
        """Show details for the selected entry."""
        entry = self._get_selected_entry()
        if entry:
            self._show_entry_details(entry)
    
    def action_hide_details(self) -> None:
        """Hide the details panel."""
        self._hide_entry_details()
    
    def action_focus_search(self) -> None:
        """Focus the search input."""
        search_input = self.query_one("#search-input", Input)
        search_input.focus()
    
    def action_clear_filters(self) -> None:
        """Clear all filters."""
        self.search_term = ""
        self.ip_filter = ""
        self.event_filter = ""
        self.date_filter = ""
        
        # Clear input fields
        self.query_one("#search-input", Input).value = ""
        self.query_one("#ip-filter", Input).value = ""
        self.query_one("#date-filter", Input).value = ""
        self.query_one("#event-filter", Select).value = ""
        
        self._apply_filters()
        self._update_display()
    
    def action_refresh(self) -> None:
        """Refresh the log data."""
        self.refresh_data()
    
    def action_show_export(self) -> None:
        """Show the export panel."""
        self._hide_all_panels()
        self.current_panel = "export"
        export_panel = self.query_one("#export-panel")
        export_panel.display = True
        self._update_export_preview()
    
    def action_show_sessions(self) -> None:
        """Show the session correlation panel."""
        self._hide_all_panels()
        self.current_panel = "sessions"
        session_panel = self.query_one("#session-panel")
        session_panel.display = True
        self._update_session_correlation()
    
    def action_show_stats(self) -> None:
        """Show the statistics panel."""
        self._hide_all_panels()
        self.current_panel = "stats"
        stats_panel = self.query_one("#stats-panel")
        stats_panel.display = True
        self._update_statistics()
    
    def _hide_all_panels(self) -> None:
        """Hide all secondary panels."""
        panels = ["#detail-panel", "#export-panel", "#session-panel", "#stats-panel"]
        for panel_id in panels:
            try:
                panel = self.query_one(panel_id)
                panel.display = False
            except:
                pass  # Panel might not exist yet
        self.current_panel = None
    
    def _update_export_preview(self) -> None:
        """Update the export preview information."""
        try:
            preview = self.query_one("#export-preview", Static)
            status = self.query_one("#export-status", Static)
            
            total_entries = len(self.filtered_entries)
            preview_text = f"Ready to export {total_entries} log entries"
            if self.search_term or self.ip_filter or self.event_filter or self.date_filter:
                preview_text += " (filtered)"
            
            preview.update(preview_text)
            status.update("Select export format above")
        except:
            pass  # Widgets might not be mounted yet
    
    def _export_to_csv(self, entries: List[LogEntry]) -> str:
        """
        Export log entries to CSV format.
        
        Args:
            entries: List of log entries to export
            
        Returns:
            CSV string representation
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Timestamp', 'Session ID', 'Event Type', 'Source IP',
            'Message', 'Command', 'File Path', 'Threat Level'
        ])
        
        # Write data rows
        for entry in entries:
            writer.writerow([
                entry.timestamp.isoformat(),
                entry.session_id,
                entry.event_type,
                entry.source_ip,
                entry.message,
                entry.command or '',
                entry.file_path or '',
                entry.threat_level or ''
            ])
        
        return output.getvalue()
    
    def _export_to_json(self, entries: List[LogEntry]) -> str:
        """
        Export log entries to JSON format.
        
        Args:
            entries: List of log entries to export
            
        Returns:
            JSON string representation
        """
        data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_entries': len(entries),
            'entries': [entry.to_dict() for entry in entries]
        }
        return json.dumps(data, indent=2)
    
    def _correlate_sessions(self) -> Dict[str, Session]:
        """
        Correlate log entries into sessions.
        
        Returns:
            Dictionary mapping session IDs to Session objects
        """
        sessions = {}
        
        # Group entries by session ID
        session_entries = defaultdict(list)
        for entry in self.filtered_entries:
            session_entries[entry.session_id].append(entry)
        
        # Create session objects
        for session_id, entries in session_entries.items():
            if not entries:
                continue
            
            # Sort entries by timestamp
            entries.sort(key=lambda e: e.timestamp)
            
            # Extract session information
            first_entry = entries[0]
            last_entry = entries[-1]
            
            commands = []
            files_accessed = []
            threat_scores = []
            
            for entry in entries:
                if entry.command:
                    commands.append(entry.command)
                if entry.file_path:
                    files_accessed.append(entry.file_path)
                if entry.threat_level:
                    # Convert threat level to numeric score
                    threat_map = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
                    threat_scores.append(threat_map.get(entry.threat_level, 0.0))
            
            # Calculate average threat score
            avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
            
            # Determine end time (None if session might still be active)
            end_time = None
            if len(entries) > 1:
                # If last entry is more than 10 minutes old, consider session ended
                time_since_last = datetime.now() - last_entry.timestamp
                if time_since_last.total_seconds() > 600:  # 10 minutes
                    end_time = last_entry.timestamp
            
            session = Session(
                session_id=session_id,
                source_ip=first_entry.source_ip,
                start_time=first_entry.timestamp,
                end_time=end_time,
                commands=list(set(commands)),  # Remove duplicates
                files_accessed=list(set(files_accessed)),  # Remove duplicates
                threat_score=avg_threat
            )
            
            sessions[session_id] = session
        
        return sessions
    
    def _update_session_correlation(self) -> None:
        """Update the session correlation display."""
        try:
            table = self.query_one("#session-table", DataTable)
            details = self.query_one("#session-details", Static)
            
            # Clear existing data
            table.clear()
            if not table.columns:
                table.add_columns(
                    "Session ID", "Source IP", "Start Time", "Duration", 
                    "Commands", "Files", "Threat Score", "Status"
                )
            
            # Correlate sessions
            self.sessions = self._correlate_sessions()
            
            # Add session data to table
            for session in self.sessions.values():
                duration = session.duration()
                duration_str = f"{duration:.1f}s" if duration else "Active"
                status = "Ended" if session.end_time else "Active"
                
                table.add_row(
                    session.session_id,
                    session.source_ip,
                    session.start_time.strftime("%H:%M:%S"),
                    duration_str,
                    str(session.command_count()),
                    str(session.file_access_count()),
                    f"{session.threat_score:.2f}",
                    status
                )
            
            # Update details
            total_sessions = len(self.sessions)
            active_sessions = sum(1 for s in self.sessions.values() if s.is_active())
            details.update(f"Total Sessions: {total_sessions} | Active: {active_sessions}")
            
        except Exception as e:
            # Handle case where widgets aren't mounted yet
            pass
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """
        Calculate statistics for the current log entries.
        
        Returns:
            Dictionary containing various statistics
        """
        if not self.filtered_entries:
            return {}
        
        # Time-based analysis
        timestamps = [entry.timestamp for entry in self.filtered_entries]
        time_span = max(timestamps) - min(timestamps)
        
        # Event type distribution
        event_types = Counter(entry.event_type for entry in self.filtered_entries)
        
        # IP address analysis
        ip_addresses = Counter(entry.source_ip for entry in self.filtered_entries)
        
        # Threat level distribution
        threat_levels = Counter(
            entry.threat_level for entry in self.filtered_entries 
            if entry.threat_level
        )
        
        # Session analysis
        sessions = self._correlate_sessions()
        session_durations = [
            s.duration() for s in sessions.values() 
            if s.duration() is not None
        ]
        
        # Command analysis
        commands = [
            entry.command for entry in self.filtered_entries 
            if entry.command
        ]
        command_types = Counter(commands)
        
        # Hourly activity distribution
        hourly_activity = Counter(entry.timestamp.hour for entry in self.filtered_entries)
        
        return {
            'total_entries': len(self.filtered_entries),
            'time_span': time_span,
            'event_types': dict(event_types),
            'top_ips': dict(ip_addresses.most_common(10)),
            'threat_levels': dict(threat_levels),
            'total_sessions': len(sessions),
            'avg_session_duration': sum(session_durations) / len(session_durations) if session_durations else 0,
            'top_commands': dict(command_types.most_common(10)),
            'hourly_activity': dict(hourly_activity),
            'unique_ips': len(ip_addresses),
            'entries_per_hour': len(self.filtered_entries) / max(1, time_span.total_seconds() / 3600)
        }
    
    def _update_statistics(self) -> None:
        """Update the statistics display."""
        try:
            content = self.query_one("#stats-content", Static)
            
            stats = self._calculate_statistics()
            if not stats:
                content.update("No data available for statistics")
                return
            
            # Format statistics display
            stats_text = f"""Log Analysis Summary:

Total Entries: {stats['total_entries']}
Time Span: {stats['time_span']}
Unique IP Addresses: {stats['unique_ips']}
Total Sessions: {stats['total_sessions']}
Average Session Duration: {stats['avg_session_duration']:.1f}s
Entries per Hour: {stats['entries_per_hour']:.1f}

Event Type Distribution:"""
            
            for event_type, count in stats['event_types'].items():
                percentage = (count / stats['total_entries']) * 100
                stats_text += f"\n  {event_type}: {count} ({percentage:.1f}%)"
            
            if stats['threat_levels']:
                stats_text += "\n\nThreat Level Distribution:"
                for threat, count in stats['threat_levels'].items():
                    percentage = (count / stats['total_entries']) * 100
                    stats_text += f"\n  {threat}: {count} ({percentage:.1f}%)"
            
            stats_text += "\n\nTop Source IPs:"
            for ip, count in list(stats['top_ips'].items())[:5]:
                percentage = (count / stats['total_entries']) * 100
                stats_text += f"\n  {ip}: {count} ({percentage:.1f}%)"
            
            if stats['top_commands']:
                stats_text += "\n\nTop Commands:"
                for cmd, count in list(stats['top_commands'].items())[:5]:
                    stats_text += f"\n  {cmd}: {count}"
            
            stats_text += "\n\nHourly Activity Distribution:"
            for hour in sorted(stats['hourly_activity'].keys()):
                count = stats['hourly_activity'][hour]
                stats_text += f"\n  {hour:02d}:00: {count} entries"
            
            content.update(stats_text)
            
        except Exception as e:
            # Handle case where widgets aren't mounted yet
            pass


class LogDetailView(Widget):
    """
    Detailed view for a single log entry with related session information.
    """
    
    DEFAULT_CSS = """
    LogDetailView {
        layout: vertical;
        height: 100%;
        padding: 1;
    }
    
    #detail-header {
        height: 3;
        background: $primary;
        padding: 1;
        text-style: bold;
    }
    
    #detail-content {
        height: 1fr;
        padding: 1;
    }
    
    #related-sessions {
        height: 40%;
        border-top: solid $surface;
        padding-top: 1;
    }
    """
    
    def __init__(self, log_entry: LogEntry, **kwargs):
        """Initialize the detail view."""
        super().__init__(**kwargs)
        self.log_entry = log_entry
        self.related_sessions: List[Session] = []
    
    def compose(self):
        """Create the detail view layout."""
        yield Static(f"Log Entry Details - {self.log_entry.session_id}", id="detail-header")
        
        with ScrollableContainer(id="detail-content"):
            yield Static(self._format_entry_details(), id="entry-details")
        
        with Container(id="related-sessions"):
            yield Static("Related Session Information", classes="section-header")
            yield DataTable(id="session-table", zebra_stripes=True)
    
    def on_mount(self) -> None:
        """Initialize the detail view when mounted."""
        self._setup_session_table()
        self._load_related_sessions()
    
    def _setup_session_table(self) -> None:
        """Set up the session information table."""
        table = self.query_one("#session-table", DataTable)
        table.add_columns("Session ID", "Start Time", "Duration", "Commands", "Files", "Threat Score")
    
    def _format_entry_details(self) -> str:
        """Format the log entry details for display."""
        entry = self.log_entry
        return f"""Timestamp: {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Session ID: {entry.session_id}
Event Type: {entry.event_type}
Source IP: {entry.source_ip}
Threat Level: {entry.threat_level or 'None'}

Message:
{entry.message}

Command: {entry.command or 'N/A'}
File Path: {entry.file_path or 'N/A'}

JSON Representation:
{entry.to_json()}"""
    
    def _load_related_sessions(self) -> None:
        """Load sessions related to this log entry."""
        # This would typically query a data source for related sessions
        # For now, create a sample related session
        sample_session = Session(
            session_id=self.log_entry.session_id,
            source_ip=self.log_entry.source_ip,
            start_time=self.log_entry.timestamp - timedelta(minutes=5),
            end_time=self.log_entry.timestamp + timedelta(minutes=10),
            commands=["ls -la", "cat /etc/passwd", "wget malware.sh"],
            files_accessed=["/etc/passwd", "/tmp/malware.sh"],
            threat_score=0.7
        )
        
        self.related_sessions = [sample_session]
        self._update_session_table()
    
    def _update_session_table(self) -> None:
        """Update the session table with related session data."""
        table = self.query_one("#session-table", DataTable)
        table.clear()
        
        for session in self.related_sessions:
            duration = session.duration()
            duration_str = f"{duration:.1f}s" if duration else "Active"
            
            table.add_row(
                session.session_id,
                session.start_time.strftime("%H:%M:%S"),
                duration_str,
                str(session.command_count()),
                str(session.file_access_count()),
                f"{session.threat_score:.2f}"
            )