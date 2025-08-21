#!/usr/bin/env python3
"""
Simple TUI honeypot monitor that works without complex service coordination.
"""

import sys
import os
from datetime import datetime
sys.path.insert(0, 'src')

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Button
from textual.binding import Binding

from honeypot_monitor.services.log_parser import KippoLogParser

class SimpleHoneypotMonitor(App):
    """Simple honeypot monitor TUI."""
    
    CSS = """
    DataTable {
        height: 1fr;
    }
    
    #stats {
        height: 8;
        border: solid $primary;
        margin: 1;
        padding: 1;
    }
    
    #controls {
        height: 3;
        margin: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def __init__(self, log_path):
        super().__init__()
        self.log_path = log_path
        self.parser = KippoLogParser()
        self.entries = []
        
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container():
            with Horizontal():
                with Vertical():
                    yield Static("Honeypot Activity", id="title")
                    yield Static("", id="stats")
                    
                    with Horizontal(id="controls"):
                        yield Button("Refresh", id="refresh-btn")
                        yield Button("Quit", id="quit-btn")
                    
                    yield DataTable(id="activity-table")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the table and load data."""
        table = self.query_one("#activity-table", DataTable)
        table.add_columns("Time", "Source IP", "Event", "Message")
        self.load_data()
    
    def load_data(self) -> None:
        """Load and display log data."""
        try:
            # Read recent log entries
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-100:] if len(lines) > 100 else lines
            
            # Parse entries
            self.entries = []
            for line in recent_lines:
                entry = self.parser.parse_entry_safe(line.strip())
                if entry:
                    self.entries.append(entry)
            
            # Update table
            table = self.query_one("#activity-table", DataTable)
            table.clear()
            
            for entry in reversed(self.entries[-50:]):  # Show last 50, newest first
                table.add_row(
                    entry.timestamp.strftime("%H:%M:%S"),
                    entry.source_ip,
                    entry.event_type,
                    entry.message[:60] + "..." if len(entry.message) > 60 else entry.message
                )
            
            # Update stats
            self.update_stats()
            
        except Exception as e:
            stats = self.query_one("#stats", Static)
            stats.update(f"Error loading data: {e}")
    
    def update_stats(self) -> None:
        """Update the statistics display."""
        if not self.entries:
            return
            
        # Count events
        event_counts = {}
        ip_counts = {}
        
        for entry in self.entries:
            event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1
            ip_counts[entry.source_ip] = ip_counts.get(entry.source_ip, 0) + 1
        
        # Format stats
        total_events = len(self.entries)
        unique_ips = len([ip for ip in ip_counts.keys() if ip != "0.0.0.0"])
        
        stats_text = f"Total Events: {total_events} | Unique IPs: {unique_ips} | "
        stats_text += f"Auth: {event_counts.get('authentication', 0)} | "
        stats_text += f"Commands: {event_counts.get('command', 0)} | "
        stats_text += f"Connections: {event_counts.get('connection', 0)}"
        
        stats = self.query_one("#stats", Static)
        stats.update(stats_text)
    
    def action_refresh(self) -> None:
        """Refresh the data."""
        self.load_data()
    
    def on_button_pressed(self, event) -> None:
        """Handle button presses."""
        if event.button.id == "refresh-btn":
            self.action_refresh()
        elif event.button.id == "quit-btn":
            self.exit()

if __name__ == "__main__":
    log_path = "/private/var/folders/wf/wk5_cgz15tx8368cbf_68_2c0000gr/T/tmp-27121-guAJXT0KUdwY/cowrie.log"
    
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)
    
    app = SimpleHoneypotMonitor(log_path)
    app.run()