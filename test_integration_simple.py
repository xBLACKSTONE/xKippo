#!/usr/bin/env python3
"""
Simple integration test for service coordination without pytest.
"""

import sys
import os
import threading
import time
from datetime import datetime
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from honeypot_monitor.services.event_manager import EventManager, EventType, Event
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.models.threat_assessment import ThreatAssessment
from honeypot_monitor.config.settings import Settings, HoneypotSettings, MonitoringSettings, AnalysisSettings, IRCSettings


def test_event_manager():
    """Test basic event manager functionality."""
    print("Testing EventManager...")
    
    event_manager = EventManager(worker_threads=1)
    callback_called = threading.Event()
    received_event = None
    
    def test_callback(event: Event):
        nonlocal received_event
        received_event = event
        callback_called.set()
    
    # Subscribe to events
    event_manager.subscribe(EventType.LOG_ENTRY, test_callback)
    
    # Publish an event
    test_data = {"test": "data"}
    success = event_manager.publish(EventType.LOG_ENTRY, test_data, "test_source")
    
    assert success, "Event publishing failed"
    
    # Wait for callback to be called
    assert callback_called.wait(timeout=2.0), "Callback was not called"
    assert received_event is not None, "No event received"
    assert received_event.event_type == EventType.LOG_ENTRY, "Wrong event type"
    assert received_event.data == test_data, "Wrong event data"
    assert received_event.source == "test_source", "Wrong event source"
    
    event_manager.shutdown()
    print("✓ EventManager test passed")


def test_log_entry_creation():
    """Test log entry creation and processing."""
    print("Testing LogEntry creation...")
    
    log_entry = LogEntry(
        timestamp=datetime.now(),
        session_id="test_session",
        event_type="command",
        source_ip="192.168.1.100",
        message="test command",
        command="ls -la"
    )
    
    assert log_entry.session_id == "test_session", "Wrong session ID"
    assert log_entry.source_ip == "192.168.1.100", "Wrong source IP"
    assert log_entry.command == "ls -la", "Wrong command"
    
    print("✓ LogEntry creation test passed")


def test_threat_assessment_creation():
    """Test threat assessment creation."""
    print("Testing ThreatAssessment creation...")
    
    threat = ThreatAssessment(
        severity="high",
        category="exploitation",
        confidence=0.9,
        indicators=["test indicator"],
        recommended_action="investigate"
    )
    
    assert threat.severity == "high", "Wrong severity"
    assert threat.category == "exploitation", "Wrong category"
    assert threat.confidence == 0.9, "Wrong confidence"
    assert "test indicator" in threat.indicators, "Missing indicator"
    
    print("✓ ThreatAssessment creation test passed")


def test_settings_creation():
    """Test settings creation."""
    print("Testing Settings creation...")
    
    settings = Settings(
        honeypot=HoneypotSettings(
            log_path="/tmp/test_kippo.log",
            log_format="kippo_default"
        ),
        monitoring=MonitoringSettings(
            refresh_interval=1.0,
            max_entries_memory=1000
        ),
        analysis=AnalysisSettings(
            threat_threshold="medium",
            custom_rules_path="./rules/"
        ),
        irc=IRCSettings(
            enabled=False,
            server="irc.test.com",
            port=6667,
            channel="#test",
            nickname="test-bot",
            ssl=False
        )
    )
    
    assert settings.honeypot.log_path == "/tmp/test_kippo.log", "Wrong log path"
    assert settings.monitoring.max_entries_memory == 1000, "Wrong memory limit"
    assert settings.analysis.threat_threshold == "medium", "Wrong threat threshold"
    assert settings.irc.enabled == False, "IRC should be disabled"
    
    print("✓ Settings creation test passed")


def test_event_flow():
    """Test complete event flow."""
    print("Testing event flow...")
    
    event_manager = EventManager(worker_threads=1)
    events_received = []
    
    def log_handler(event: Event):
        events_received.append(('log', event))
    
    def threat_handler(event: Event):
        events_received.append(('threat', event))
    
    def new_host_handler(event: Event):
        events_received.append(('new_host', event))
    
    # Subscribe to different event types
    event_manager.subscribe(EventType.LOG_ENTRY, log_handler)
    event_manager.subscribe(EventType.THREAT_DETECTED, threat_handler)
    event_manager.subscribe(EventType.NEW_HOST, new_host_handler)
    
    # Publish different types of events
    log_entry = LogEntry(
        timestamp=datetime.now(),
        session_id="test",
        event_type="command",
        source_ip="192.168.1.1",
        message="test"
    )
    
    threat = ThreatAssessment(
        severity="high",
        category="exploitation",
        confidence=0.9,
        indicators=["test"],
        recommended_action="investigate"
    )
    
    # Publish events
    event_manager.publish_log_entry(log_entry)
    event_manager.publish_threat_detected(threat, "192.168.1.1", log_entry)
    event_manager.publish_new_host("192.168.1.1", datetime.now())
    
    # Wait for processing
    time.sleep(0.2)
    
    # Verify events were received
    assert len(events_received) == 3, f"Expected 3 events, got {len(events_received)}"
    
    event_types = [event[0] for event in events_received]
    assert 'log' in event_types, "Log event not received"
    assert 'threat' in event_types, "Threat event not received"
    assert 'new_host' in event_types, "New host event not received"
    
    event_manager.shutdown()
    print("✓ Event flow test passed")


def main():
    """Run all tests."""
    print("Running integration tests...")
    print("=" * 50)
    
    try:
        test_event_manager()
        test_log_entry_creation()
        test_threat_assessment_creation()
        test_settings_creation()
        test_event_flow()
        
        print("=" * 50)
        print("✓ All integration tests passed!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())