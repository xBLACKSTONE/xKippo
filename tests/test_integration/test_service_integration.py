"""
Integration tests for service coordination and event-driven architecture.
"""

import pytest
import threading
import time
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.honeypot_monitor.services.event_manager import EventManager, EventType, Event
from src.honeypot_monitor.services.service_coordinator import ServiceCoordinator
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment
from src.honeypot_monitor.config.settings import Settings, HoneypotSettings, MonitoringSettings, AnalysisSettings, IRCSettings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    return Settings(
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
            enabled=False,  # Disable IRC for testing
            server="irc.test.com",
            port=6667,
            channel="#test",
            nickname="test-bot",
            ssl=False
        )
    )


class TestEventManager:
    """Test the event manager functionality."""
    
    def test_event_manager_initialization(self):
        """Test event manager initializes correctly."""
        event_manager = EventManager(max_queue_size=100, worker_threads=1)
        
        assert event_manager.max_queue_size == 100
        assert event_manager.worker_threads == 1
        assert len(event_manager.workers) == 1
        assert not event_manager.shutdown_event.is_set()
        
        event_manager.shutdown()
    
    def test_event_subscription_and_publishing(self):
        """Test event subscription and publishing."""
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
        
        assert success
        
        # Wait for callback to be called
        assert callback_called.wait(timeout=2.0)
        assert received_event is not None
        assert received_event.event_type == EventType.LOG_ENTRY
        assert received_event.data == test_data
        assert received_event.source == "test_source"
        
        event_manager.shutdown()
    
    def test_event_manager_statistics(self):
        """Test event manager statistics tracking."""
        event_manager = EventManager(worker_threads=1)
        
        # Publish some events
        for i in range(5):
            event_manager.publish(EventType.LOG_ENTRY, {"test": i}, "test")
        
        # Wait a bit for processing
        time.sleep(0.1)
        
        stats = event_manager.get_statistics()
        assert stats["events_processed"] >= 0
        assert stats["events_dropped"] == 0
        assert stats["max_queue_size"] == 1000
        assert stats["worker_threads"] == 1
        
        event_manager.shutdown()


class TestServiceCoordinator:
    """Test the service coordinator functionality."""
    
    @patch('src.honeypot_monitor.services.service_coordinator.LogMonitor')
    @patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser')
    @patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer')
    @patch('src.honeypot_monitor.services.service_coordinator.AlertManager')
    def test_service_coordinator_initialization(self, mock_alert_manager, mock_threat_analyzer, 
                                              mock_log_parser, mock_log_monitor, mock_settings):
        """Test service coordinator initializes all services."""
        coordinator = ServiceCoordinator(mock_settings)
        
        assert coordinator.settings == mock_settings
        assert coordinator.event_manager is not None
        assert not coordinator.is_running
        
        # Check that services were initialized
        mock_log_parser.assert_called_once()
        mock_log_monitor.assert_called_once()
        mock_threat_analyzer.assert_called_once_with(mock_settings.analysis)
        mock_alert_manager.assert_called_once()
        
        coordinator.shutdown()
    
    @patch('src.honeypot_monitor.services.service_coordinator.LogMonitor')
    @patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser')
    @patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer')
    @patch('src.honeypot_monitor.services.service_coordinator.AlertManager')
    @patch('os.path.exists')
    @patch('os.access')
    def test_service_coordinator_start_stop(self, mock_access, mock_exists, mock_alert_manager, 
                                          mock_threat_analyzer, mock_log_parser, mock_log_monitor, 
                                          mock_settings):
        """Test service coordinator start and stop functionality."""
        # Mock file system checks
        mock_exists.return_value = True
        mock_access.return_value = True
        
        # Mock service instances
        mock_log_monitor_instance = Mock()
        mock_log_monitor.return_value = mock_log_monitor_instance
        
        mock_alert_manager_instance = Mock()
        mock_alert_manager.return_value = mock_alert_manager_instance
        
        coordinator = ServiceCoordinator(mock_settings)
        
        # Test start
        success = coordinator.start()
        assert success
        assert coordinator.is_running
        
        # Verify log monitor was started
        mock_log_monitor_instance.register_callback.assert_called_once()
        mock_log_monitor_instance.start_monitoring.assert_called_once_with(mock_settings.honeypot.log_path)
        
        # Test stop
        coordinator.stop()
        assert not coordinator.is_running
        mock_log_monitor_instance.stop_monitoring.assert_called_once()
        
        coordinator.shutdown()
    
    def test_service_coordinator_status(self, mock_settings):
        """Test service coordinator status reporting."""
        with patch('src.honeypot_monitor.services.service_coordinator.LogMonitor'), \
             patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser'), \
             patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer'), \
             patch('src.honeypot_monitor.services.service_coordinator.AlertManager'):
            
            coordinator = ServiceCoordinator(mock_settings)
            
            status = coordinator.get_status()
            
            assert 'is_running' in status
            assert 'services' in status
            assert 'errors' in status
            assert 'event_manager' in status
            
            assert status['is_running'] == False
            assert 'log_monitor' in status['services']
            assert 'threat_analyzer' in status['services']
            assert 'alert_manager' in status['services']
            
            coordinator.shutdown()


class TestEventDrivenIntegration:
    """Test event-driven integration between services."""
    
    def test_log_entry_processing_flow(self, mock_settings):
        """Test complete log entry processing flow through events."""
        with patch('src.honeypot_monitor.services.service_coordinator.LogMonitor') as mock_log_monitor, \
             patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser'), \
             patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer'), \
             patch('src.honeypot_monitor.services.service_coordinator.AlertManager') as mock_alert_manager, \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            
            # Setup mocks
            mock_log_monitor_instance = Mock()
            mock_log_monitor.return_value = mock_log_monitor_instance
            
            mock_alert_manager_instance = Mock()
            mock_alert_manager_instance.process_log_entry.return_value = []
            mock_alert_manager.return_value = mock_alert_manager_instance
            
            coordinator = ServiceCoordinator(mock_settings)
            coordinator.start()
            
            # Create a test log entry
            log_entry = LogEntry(
                timestamp=datetime.now(),
                session_id="test_session",
                event_type="command",
                source_ip="192.168.1.100",
                message="test command",
                command="ls -la"
            )
            
            # Simulate log entry callback
            callback = mock_log_monitor_instance.register_callback.call_args[0][0]
            callback(log_entry)
            
            # Wait for event processing
            time.sleep(0.1)
            
            # Verify alert manager was called
            mock_alert_manager_instance.process_log_entry.assert_called_once_with(log_entry)
            
            coordinator.shutdown()
    
    def test_error_handling_and_recovery(self, mock_settings):
        """Test error handling and recovery mechanisms."""
        with patch('src.honeypot_monitor.services.service_coordinator.LogMonitor') as mock_log_monitor, \
             patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser'), \
             patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer'), \
             patch('src.honeypot_monitor.services.service_coordinator.AlertManager'):
            
            coordinator = ServiceCoordinator(mock_settings)
            
            # Test system error handling
            coordinator.event_manager.publish_system_error("Test error", Exception("Test exception"))
            
            # Wait for event processing
            time.sleep(0.1)
            
            # Verify error was logged (we can't easily test logging, but we can verify no crash)
            assert coordinator.event_manager is not None
            
            coordinator.shutdown()
    
    def test_graceful_shutdown(self, mock_settings):
        """Test graceful shutdown procedures."""
        with patch('src.honeypot_monitor.services.service_coordinator.LogMonitor') as mock_log_monitor, \
             patch('src.honeypot_monitor.services.service_coordinator.KippoLogParser'), \
             patch('src.honeypot_monitor.services.service_coordinator.ThreatAnalyzer'), \
             patch('src.honeypot_monitor.services.service_coordinator.AlertManager'), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            
            mock_log_monitor_instance = Mock()
            mock_log_monitor.return_value = mock_log_monitor_instance
            
            coordinator = ServiceCoordinator(mock_settings)
            coordinator.start()
            
            # Verify services are running
            assert coordinator.is_running
            
            # Test graceful shutdown
            coordinator.shutdown()
            
            # Verify services were stopped
            assert not coordinator.is_running
            mock_log_monitor_instance.stop_monitoring.assert_called_once()
            
            # Verify event manager was shutdown
            assert coordinator.event_manager.shutdown_event.is_set()


class TestRealTimeUpdates:
    """Test real-time update functionality."""
    
    def test_real_time_log_entry_updates(self):
        """Test real-time log entry updates to TUI components."""
        # This would test the TUI integration, but since we can't easily test
        # the TUI in unit tests, we'll test the event flow
        
        event_manager = EventManager(worker_threads=1)
        updates_received = []
        
        def mock_tui_update(event: Event):
            updates_received.append(event)
        
        event_manager.subscribe(EventType.LOG_ENTRY, mock_tui_update)
        
        # Simulate log entry
        log_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="test",
            event_type="command",
            source_ip="192.168.1.1",
            message="test"
        )
        
        event_manager.publish_log_entry(log_entry)
        
        # Wait for processing
        time.sleep(0.1)
        
        assert len(updates_received) == 1
        assert updates_received[0].event_type == EventType.LOG_ENTRY
        assert updates_received[0].data["log_entry"] == log_entry
        
        event_manager.shutdown()
    
    def test_threat_detection_updates(self):
        """Test threat detection updates."""
        event_manager = EventManager(worker_threads=1)
        threat_updates = []
        
        def mock_threat_handler(event: Event):
            threat_updates.append(event)
        
        event_manager.subscribe(EventType.THREAT_DETECTED, mock_threat_handler)
        
        # Simulate threat detection
        threat = ThreatAssessment(
            severity="high",
            category="exploitation",
            confidence=0.9,
            indicators=["test indicator"],
            recommended_action="investigate"
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            session_id="test",
            event_type="command",
            source_ip="192.168.1.1",
            message="test"
        )
        
        event_manager.publish_threat_detected(threat, "192.168.1.1", log_entry)
        
        # Wait for processing
        time.sleep(0.1)
        
        assert len(threat_updates) == 1
        assert threat_updates[0].event_type == EventType.THREAT_DETECTED
        assert threat_updates[0].data["threat"] == threat
        assert threat_updates[0].data["source_ip"] == "192.168.1.1"
        
        event_manager.shutdown()


if __name__ == "__main__":
    pytest.main([__file__])