#!/usr/bin/env python3
"""
Simple test script to verify Cowrie log parsing is working.
Run this from the honeypot monitor directory to test parsing.
"""

import sys
import os
sys.path.insert(0, 'src')

from honeypot_monitor.services.log_parser import KippoLogParser
from datetime import datetime

def test_cowrie_parsing():
    """Test parsing of actual Cowrie log lines."""
    
    # Sample Cowrie log lines from your system
    test_lines = [
        "2025-08-20T22:37:40.863200Z [HoneyPotSSHTransport,2930,35.240.141.162] login attempt [b'root'/b'root'] failed",
        "2025-08-20T22:38:44.087265Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 35.240.141.162:39654 (45.79.209.210:2222) [session: 762fc373a6b2]",
        "2025-08-20T22:38:47.081582Z [HoneyPotSSHTransport,2931,35.240.141.162] Connection lost after 3.0 seconds",
        "2025-08-20T22:39:49.681173Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,2932,35.240.141.162] CMD: uname -s -v -n -r -m"
    ]
    
    print("Testing Cowrie log parsing...")
    print("=" * 50)
    
    # Create parser
    parser = KippoLogParser()
    
    # Test each line
    for i, line in enumerate(test_lines, 1):
        print(f"\nTest {i}: {line[:80]}...")
        
        try:
            # Test safe parsing
            entry = parser.parse_entry_safe(line)
            
            if entry:
                print(f"✅ SUCCESS: Parsed as {entry.event_type}")
                print(f"   Source IP: {entry.source_ip}")
                print(f"   Session: {entry.session_id}")
                print(f"   Message: {entry.message[:60]}...")
                if entry.command:
                    print(f"   Command: {entry.command}")
            else:
                print("❌ FAILED: parse_entry_safe returned None")
                
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
    
    print("\n" + "=" * 50)
    print("Testing supported formats...")
    print(f"Supported formats: {parser._supported_formats}")
    
    print("\nTesting pattern matching...")
    for pattern_name, pattern in parser._patterns.items():
        print(f"Pattern '{pattern_name}': {pattern.pattern[:80]}...")

if __name__ == "__main__":
    test_cowrie_parsing()