"""
Tests for memory management and performance optimization.
"""

import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from honeypot_monitor.services.memory_manager import MemoryManager, MemoryStats
from honeypot_monitor.services.performance_monitor import PerformanceMonitor, PerformanceMetrics
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.models.threat_assessment import ThreatAssessment
from honeypot_monitor.models.irc_alert import IRCAlert


class TestMemoryManager:
    """Test memory management functionality."""
    
    def test_memory_manager_initialization(self):
        """Test memory manager initializes correctly."""
        memory_manager = MemoryManager(
            max_log_entries=100,
            max_sessions=50,
            max_threats=200,
            max_alerts=75,
            cleanup_interval=60,
            memory_threshold=80.0
        )
        
        assert memory_manager.max_log_entries == 100
        assert memory_manager.max_sessions == 50
        assert memory_manager.max_threats == 200
        assert memory_manager.max_alerts == 75
        assert memory_manager.cleanup_interval == 60
        assert memory_manager.memory_threshold == 80.0
        
        # Check initial state
        assert len(memory_manager.log_entries) == 0
        assert len(memory_manager.sessions) == 0
        assert len(memory_manager.threat_assessments) == 0
        assert len(memory_manager.alerts) == 0
    
    def test_log_entry_management(self):
        """Test log entry storage and limits."""
        memory_manager = MemoryManager(max_log_entries=5)
        
        # Add log entries
        for i in range(10):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                event_type="command",
                source_ip=f"192.168.1.{i}",
                message=f"test message {i}"
            )
            memory_manager.add_log_entry(entry)
        
        # Should only keep the last 5 entries due to deque maxlen
        assert len(memory_manager.log_entries) == 5
        
        # Get entries
        entries = memory_manager.get_log_entries()
        assert len(entries) == 5
        
        # Get limited entries
        limited_entries = memory_manager.get_log_entries(limit=3)
        assert len(limited_entries) == 3
    
    def test_memory_cleanup(self):
        """Test memory cleanup functionality."""
        memory_manager = MemoryManager(
            max_log_entries=100,
            max_sessions=10,
            cleanup_interval=1
        )
        
        # Add some test data
        for i in range(15):
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                event_type="command",
                source_ip=f"192.168.1.{i}",
                message=f"test {i}"
            )
            memory_manager.add_log_entry(entry)
        
        # Force cleanup
        cleanup_results = memory_manager.force_cleanup()
        
        assert isinstance(cleanup_results, dict)
        assert 'entries_cleaned' in cleanup_results
        assert 'sessions_cleaned' in cleanup_results
    
    def test_memory_statistics(self):
        """Test memory statistics collection."""
        memory_manager = MemoryManager()
        
        # Add some data
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id="test_session",
            event_type="command",
            source_ip="192.168.1.1",
            message="test"
        )
        memory_manager.add_log_entry(entry)
        
        # Get statistics
        stats = memory_manager.get_memory_stats()
        
        assert isinstance(stats, MemoryStats)
        assert stats.log_entries_count == 1
        assert stats.total_memory_mb > 0
        assert stats.process_memory_mb > 0
    
    def test_background_cleanup(self):
        """Test background cleanup thread."""
        memory_manager = MemoryManager(cleanup_interval=0.1)  # Very short interval for testing
        
        # Start memory manager
        memory_manager.start()
        assert memory_manager.is_running
        
        # Wait a bit for background thread to run
        time.sleep(0.2)
        
        # Stop memory manager
        memory_manager.stop()
        assert not memory_manager.is_running


class TestPerformanceMonitor:
    """Test performance monitoring functionality."""
    
    def test_performance_monitor_initialization(self):
        """Test performance monitor initializes correctly."""
        perf_monitor = PerformanceMonitor(
            collection_interval=1.0,
            history_size=100,
            cpu_threshold=75.0,
            memory_threshold=80.0
        )
        
        assert perf_monitor.collection_interval == 1.0
        assert perf_monitor.history_size == 100
        assert perf_monitor.cpu_threshold == 75.0
        assert perf_monitor.memory_threshold == 80.0
        
        # Check initial state
        assert len(perf_monitor.metrics_history) == 0
        assert not perf_monitor.is_running
    
    def test_metrics_collection(self):
        """Test performance metrics collection."""
        perf_monitor = PerformanceMonitor()
        
        # Get current metrics
        metrics = perf_monitor.get_current_metrics()
        
        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.timestamp is not None
        assert metrics.cpu_percent >= 0
        assert metrics.memory_percent >= 0
        assert metrics.memory_mb > 0
    
    def test_application_metrics_recording(self):
        """Test application-specific metrics recording."""
        perf_monitor = PerformanceMonitor()
        
        # Record some metrics
        perf_monitor.record_log_entry()
        perf_monitor.record_log_entry()
        perf_monitor.record_threat_analysis_time(25.5)
        perf_monitor.record_event_processing_time(10.2)
        perf_monitor.record_error()
        
        # Check counters
        assert perf_monitor.log_entries_counter == 2
        assert len(perf_monitor.threat_analysis_times) == 1
        assert len(perf_monitor.event_processing_times) == 1
        assert perf_monitor.error_counter == 1
    
    def test_queue_tracking(self):
        """Test queue size tracking."""
        perf_monitor = PerformanceMonitor()
        
        # Mock queue
        mock_queue_size = 42
        
        def get_queue_size():
            return mock_queue_size
        
        # Register queue tracker
        perf_monitor.register_queue_tracker("test_queue", get_queue_size)
        
        # Get metrics
        metrics = perf_monitor.get_current_metrics()
        
        assert "test_queue" in metrics.queue_sizes
        assert metrics.queue_sizes["test_queue"] == 42
    
    def test_performance_statistics(self):
        """Test performance statistics aggregation."""
        perf_monitor = PerformanceMonitor()
        
        # Add some mock metrics to history
        for i in range(5):
            metrics = PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_percent=50.0 + i,
                memory_percent=60.0 + i,
                memory_mb=100.0 + i,
                disk_io_read_mb=0.0,
                disk_io_write_mb=0.0,
                network_bytes_sent=0.0,
                network_bytes_recv=0.0,
                thread_count=10,
                file_descriptors=50,
                log_entries_per_second=10.0 + i,
                threat_analysis_time_ms=20.0 + i,
                event_processing_time_ms=5.0 + i
            )
            perf_monitor.metrics_history.append(metrics)
        
        # Get statistics
        stats = perf_monitor.get_performance_stats()
        
        assert stats.avg_cpu_percent == 52.0  # (50+51+52+53+54)/5
        assert stats.max_cpu_percent == 54.0
        assert stats.avg_memory_percent == 62.0
        assert stats.max_memory_percent == 64.0
        assert len(stats.recommendations) >= 0
    
    def test_bottleneck_detection(self):
        """Test bottleneck detection."""
        perf_monitor = PerformanceMonitor(cpu_threshold=50.0, memory_threshold=60.0)
        
        # Add high-usage metrics
        high_usage_metrics = PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_percent=95.0,  # High CPU
            memory_percent=90.0,  # High memory
            memory_mb=1000.0,
            disk_io_read_mb=0.0,
            disk_io_write_mb=0.0,
            network_bytes_sent=0.0,
            network_bytes_recv=0.0,
            thread_count=10,
            file_descriptors=50,
            threat_analysis_time_ms=150.0,  # Slow threat analysis
            event_processing_time_ms=75.0  # Slow event processing
        )
        perf_monitor.metrics_history.append(high_usage_metrics)
        
        # Get bottlenecks
        bottlenecks = perf_monitor.get_bottlenecks()
        
        assert len(bottlenecks) > 0
        
        # Check for expected bottleneck types
        bottleneck_types = [b['type'] for b in bottlenecks]
        assert 'cpu' in bottleneck_types
        assert 'memory' in bottleneck_types
    
    def test_alert_callbacks(self):
        """Test performance alert callbacks."""
        perf_monitor = PerformanceMonitor(cpu_threshold=50.0)
        
        alerts_received = []
        
        def alert_callback(message, metrics):
            alerts_received.append((message, metrics))
        
        # Register callback
        perf_monitor.register_alert_callback(alert_callback)
        
        # Create high CPU metrics
        high_cpu_metrics = PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_percent=75.0,  # Above threshold
            memory_percent=30.0,
            memory_mb=100.0,
            disk_io_read_mb=0.0,
            disk_io_write_mb=0.0,
            network_bytes_sent=0.0,
            network_bytes_recv=0.0,
            thread_count=10,
            file_descriptors=50
        )
        
        # Trigger alert check
        perf_monitor._check_performance_alerts(high_cpu_metrics)
        
        # Should have received CPU alert
        assert len(alerts_received) == 1
        assert "CPU usage" in alerts_received[0][0]
    
    def test_background_monitoring(self):
        """Test background monitoring thread."""
        perf_monitor = PerformanceMonitor(collection_interval=0.1)  # Very short interval
        
        # Start monitoring
        perf_monitor.start()
        assert perf_monitor.is_running
        
        # Wait for some metrics to be collected
        time.sleep(0.3)
        
        # Should have collected some metrics
        assert len(perf_monitor.metrics_history) > 0
        
        # Stop monitoring
        perf_monitor.stop()
        assert not perf_monitor.is_running


class TestIntegratedPerformanceMemory:
    """Test integrated performance and memory management."""
    
    def test_memory_performance_integration(self):
        """Test memory manager and performance monitor working together."""
        memory_manager = MemoryManager(max_log_entries=100)
        perf_monitor = PerformanceMonitor()
        
        # Start both services
        memory_manager.start()
        perf_monitor.start()
        
        try:
            # Add some load
            for i in range(50):
                entry = LogEntry(
                    timestamp=datetime.now(),
                    session_id=f"session_{i}",
                    event_type="command",
                    source_ip=f"192.168.1.{i % 10}",
                    message=f"test command {i}"
                )
                
                # Record in both systems
                memory_manager.add_log_entry(entry)
                perf_monitor.record_log_entry()
                
                # Simulate some processing time
                time.sleep(0.001)
            
            # Wait a bit for background processing
            time.sleep(0.1)
            
            # Check that both systems have data
            memory_stats = memory_manager.get_memory_stats()
            perf_stats = perf_monitor.get_performance_stats()
            
            assert memory_stats.log_entries_count == 50
            assert perf_stats.total_errors == 0
            
        finally:
            # Clean up
            memory_manager.stop()
            perf_monitor.stop()
    
    def test_memory_cleanup_under_load(self):
        """Test memory cleanup behavior under load."""
        memory_manager = MemoryManager(
            max_log_entries=20,  # Small limit to trigger cleanup
            cleanup_interval=0.1  # Frequent cleanup
        )
        
        memory_manager.start()
        
        try:
            # Add many entries quickly
            for i in range(100):
                entry = LogEntry(
                    timestamp=datetime.now(),
                    session_id=f"session_{i}",
                    event_type="command",
                    source_ip=f"192.168.1.{i % 5}",
                    message=f"test {i}"
                )
                memory_manager.add_log_entry(entry)
            
            # Wait for cleanup
            time.sleep(0.2)
            
            # Should be limited by maxlen
            assert len(memory_manager.log_entries) <= 20
            
            # Should have cleanup statistics
            cleanup_stats = memory_manager.get_cleanup_stats()
            assert cleanup_stats['total_cleanups'] >= 0
            
        finally:
            memory_manager.stop()


def main():
    """Run all tests."""
    print("Running memory and performance tests...")
    
    # Memory manager tests
    test_memory = TestMemoryManager()
    test_memory.test_memory_manager_initialization()
    test_memory.test_log_entry_management()
    test_memory.test_memory_cleanup()
    test_memory.test_memory_statistics()
    test_memory.test_background_cleanup()
    print("✓ Memory manager tests passed")
    
    # Performance monitor tests
    test_perf = TestPerformanceMonitor()
    test_perf.test_performance_monitor_initialization()
    test_perf.test_metrics_collection()
    test_perf.test_application_metrics_recording()
    test_perf.test_queue_tracking()
    test_perf.test_performance_statistics()
    test_perf.test_bottleneck_detection()
    test_perf.test_alert_callbacks()
    test_perf.test_background_monitoring()
    print("✓ Performance monitor tests passed")
    
    # Integration tests
    test_integration = TestIntegratedPerformanceMemory()
    test_integration.test_memory_performance_integration()
    test_integration.test_memory_cleanup_under_load()
    print("✓ Integration tests passed")
    
    print("✓ All memory and performance tests passed!")


if __name__ == "__main__":
    main()