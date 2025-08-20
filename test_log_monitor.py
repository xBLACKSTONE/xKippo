#!/usr/bin/env python3
"""
Simple test script to verify log monitor is working.
Run this from the honeypot monitor directory to test monitoring.
"""

import sys
import os
import time
sys.path.insert(0, 'src')

from honeypot_monitor.services.log_monitor import LogMonitor
from honeypot_monitor.services.log_parser import KippoLogParser

def test_log_monitor():
    """Test if log monitor can start and read a file."""
    
    # Your actual log file path
    log_path = "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
    
    print("Testing Log Monitor...")
    print("=" * 50)
    
    # Check if log file exists
    if not os.path.exists(log_path):
        print(f"❌ ERROR: Log file not found: {log_path}")
        return
    
    print(f"✅ Log file exists: {log_path}")
    
    # Check file permissions
    if not os.access(log_path, os.R_OK):
        print(f"❌ ERROR: Cannot read log file: {log_path}")
        return
    
    print(f"✅ Log file is readable")
    
    # Get file size
    file_size = os.path.getsize(log_path)
    print(f"✅ Log file size: {file_size} bytes")
    
    # Read last few lines
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
            print(f"✅ Log file has {len(lines)} lines")
            if lines:
                print(f"✅ Last line: {lines[-1].strip()[:80]}...")
    except Exception as e:
        print(f"❌ ERROR reading file: {str(e)}")
        return
    
    # Test log monitor
    print("\nTesting LogMonitor startup...")
    
    try:
        # Create parser
        parser = KippoLogParser()
        print("✅ Parser created")
        
        # Create log monitor
        monitor = LogMonitor()
        print("✅ LogMonitor created")
        
        # Add a callback to see if it gets called
        entries_received = []
        def test_callback(entry):
            entries_received.append(entry)
            print(f"✅ Callback received entry: {entry.event_type} from {entry.source_ip}")
        
        monitor.register_callback(test_callback)
        print("✅ Callback registered")
        
        # Set parser
        monitor.parser = parser
        print("✅ Parser set")
        
        # Start monitoring
        print(f"Starting monitoring of: {log_path}")
        monitor.start_monitoring(log_path)
        print("✅ Monitoring started")
        
        # Wait a bit to see if we get any callbacks
        print("Waiting 5 seconds for file changes...")
        time.sleep(5)
        
        print(f"Received {len(entries_received)} entries via callback")
        
        # Stop monitoring
        monitor.stop_monitoring()
        print("✅ Monitoring stopped")
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_log_monitor()