#!/usr/bin/env python3
"""
Debug script to test honeypot monitor startup step by step.
"""

import sys
import os
import yaml

# Add the virtual environment's site-packages to Python path
venv_path = "/home/cowrie/.honeypot-monitor/venv"
site_packages = None

# Find the site-packages directory
for root, dirs, files in os.walk(venv_path):
    if 'site-packages' in dirs:
        site_packages = os.path.join(root, 'site-packages')
        break

if site_packages:
    sys.path.insert(0, site_packages)
    print(f"DEBUG: Added to Python path: {site_packages}")
else:
    print("DEBUG: Could not find site-packages, trying src directory")
    sys.path.insert(0, 'src')

def test_basic_functionality():
    """Test each component step by step."""
    
    print("=" * 60)
    print("HONEYPOT MONITOR DEBUG TEST")
    print("=" * 60)
    
    # Test 1: Config loading
    print("\n1. Testing config loading...")
    config_path = "/home/cowrie/.honeypot-monitor/config/config.yaml"
    
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        print(f"✅ Config loaded successfully")
        print(f"   Log path: {config_data['honeypot']['log_path']}")
        print(f"   Log format: {config_data['honeypot']['log_format']}")
        log_path = config_data['honeypot']['log_path']
    except Exception as e:
        print(f"❌ Config loading failed: {e}")
        return
    
    # Test 2: Log file access
    print("\n2. Testing log file access...")
    
    if not os.path.exists(log_path):
        print(f"❌ Log file does not exist: {log_path}")
        return
    
    print(f"✅ Log file exists")
    
    if not os.access(log_path, os.R_OK):
        print(f"❌ Cannot read log file (permission denied)")
        print(f"   File owner: {os.stat(log_path).st_uid}")
        print(f"   Current user: {os.getuid()}")
        return
    
    print(f"✅ Log file is readable")
    
    # Test 3: Read log content
    print("\n3. Testing log file content...")
    
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
        
        print(f"✅ Log file has {len(lines)} lines")
        
        if lines:
            print(f"   Last line: {lines[-1].strip()[:100]}...")
        else:
            print("   ⚠️  Log file is empty")
            
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return
    
    # Test 4: Import modules
    print("\n4. Testing module imports...")
    
    try:
        from honeypot_monitor.services.log_parser import KippoLogParser
        print("✅ Log parser imported")
        
        from honeypot_monitor.services.log_monitor import LogMonitor
        print("✅ Log monitor imported")
        
        from honeypot_monitor.config.config_manager import ConfigManager
        print("✅ Config manager imported")
        
        from honeypot_monitor.services.service_coordinator import ServiceCoordinator
        print("✅ Service coordinator imported")
        
    except Exception as e:
        print(f"❌ Module import failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test 5: Parse a sample log line
    print("\n5. Testing log parsing...")
    
    if lines:
        parser = KippoLogParser()
        test_line = lines[-1].strip()
        
        try:
            entry = parser.parse_entry_safe(test_line)
            if entry:
                print(f"✅ Successfully parsed log line")
                print(f"   Event type: {entry.event_type}")
                print(f"   Source IP: {entry.source_ip}")
                print(f"   Message: {entry.message[:60]}...")
            else:
                print(f"❌ Parser returned None for line: {test_line[:80]}...")
        except Exception as e:
            print(f"❌ Parsing failed: {e}")
            print(f"   Line: {test_line[:80]}...")
    
    # Test 6: Config manager
    print("\n6. Testing config manager...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config(config_path)
        print(f"✅ Config manager loaded config successfully")
        print(f"   Log path: {config.honeypot.log_path}")
        print(f"   Log format: {config.honeypot.log_format}")
    except Exception as e:
        print(f"❌ Config manager failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test 7: Service coordinator
    print("\n7. Testing service coordinator...")
    
    try:
        coordinator = ServiceCoordinator(config)
        print(f"✅ Service coordinator created")
        
        # Try to start services
        print("   Attempting to start services...")
        success = coordinator.start()
        
        if success:
            print(f"✅ Services started successfully!")
            
            # Test log monitor
            if coordinator.log_monitor:
                print(f"   Log monitor: ✅ Running")
                print(f"   Monitoring: {coordinator.log_monitor.log_path}")
            else:
                print(f"   Log monitor: ❌ Not initialized")
                
            coordinator.stop()
            print(f"✅ Services stopped cleanly")
            
        else:
            print(f"❌ Services failed to start")
            
    except Exception as e:
        print(f"❌ Service coordinator failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("DEBUG TEST COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    test_basic_functionality()