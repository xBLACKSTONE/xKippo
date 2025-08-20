#!/usr/bin/env python3
"""
Simple, working honeypot monitor that bypasses all the complex service coordination.
"""

import sys
import os
import time
import threading
from datetime import datetime
sys.path.insert(0, 'src')

from honeypot_monitor.services.log_parser import KippoLogParser
from honeypot_monitor.models.log_entry import LogEntry

class SimpleMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.parser = KippoLogParser()
        self.running = False
        self.entries = []
        
    def start(self):
        """Start monitoring the log file."""
        print(f"Starting simple monitor for: {self.log_path}")
        
        # Read last 50 lines to populate initial data
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-50:] if len(lines) > 50 else lines
                
            print(f"Processing {len(recent_lines)} recent entries...")
            
            for line in recent_lines:
                entry = self.parser.parse_entry_safe(line.strip())
                if entry:
                    self.entries.append(entry)
                    
            print(f"Parsed {len(self.entries)} entries successfully")
            
            # Show summary
            self.show_summary()
            
        except Exception as e:
            print(f"Error: {e}")
            
    def show_summary(self):
        """Show a summary of the parsed entries."""
        if not self.entries:
            print("No entries found")
            return
            
        print("\n" + "="*60)
        print("HONEYPOT ACTIVITY SUMMARY")
        print("="*60)
        
        # Count by event type
        event_counts = {}
        ip_counts = {}
        
        for entry in self.entries:
            event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1
            ip_counts[entry.source_ip] = ip_counts.get(entry.source_ip, 0) + 1
            
        print(f"\nEvent Types:")
        for event_type, count in sorted(event_counts.items()):
            print(f"  {event_type}: {count}")
            
        print(f"\nTop Source IPs:")
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count} events")
            
        print(f"\nRecent Activity:")
        for entry in self.entries[-10:]:
            timestamp = entry.timestamp.strftime("%H:%M:%S")
            print(f"  {timestamp} | {entry.source_ip:15} | {entry.event_type:12} | {entry.message[:50]}...")
            
        print("\n" + "="*60)

if __name__ == "__main__":
    log_path = "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
    
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)
        
    monitor = SimpleMonitor(log_path)
    monitor.start()