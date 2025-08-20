#!/usr/bin/env python3
"""
Simple memory and performance test without background threads.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from datetime import datetime
from honeypot_monitor.services.memory_manager import MemoryManager, MemoryStats
from honeypot_monitor.services.performance_monitor import PerformanceMonitor, PerformanceMetrics
from honeypot_monitor.models.log_entry import LogEntry


def test_memory_manager_basic():
    """Test basic memory manager functionality without background threads."""
    print("Testing MemoryManager basic functionality...")
    
    memory_manager = MemoryManager(
        max_log_entries=10,
        max_sessions=5,
        cleanup_interval=300  # Long interval to avoid background thread issues
    )
    
    # Test initialization
    assert memory_manager.max_log_entries == 10
    assert len(memory_manager.log_entries) == 0
    
    # Test adding log entries
    for i in range(15):
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id=f"session_{i}",
            event_type="command",
            source_ip=f"192.168.1.{i}",
            message=f"test message {i}"
        )
        memory_manager.add_log_entry(entry)
    
    # Should only keep 10 entries due to deque maxlen
    assert len(memory_manager.log_entries) == 10
    
    # Test getting entries
    entries = memory_manager.get_log_entries()
    assert len(entries) == 10
    
    # Test limited retrieval
    limited = memory_manager.get_log_entries(limit=5)
    assert len(limited) == 5
    
    # Test memory stats
    stats = memory_manager.get_memory_stats()
    assert isinstance(stats, MemoryStats)
    assert stats.log_entries_count == 10
    
    # Test cleanup
    cleanup_results = memory_manager.force_cleanup()
    assert isinstance(cleanup_results, dict)
    
    print("✓ MemoryManager basic test passed")


def test_performance_monitor_basic():
    """Test basic performance monitor functionality without background threads."""
    print("Testing PerformanceMonitor basic functionality...")
    
    perf_monitor = PerformanceMonitor(
        collection_interval=300,  # Long interval to avoid background thread issues
        history_size=100
    )
    
    # Test initialization
    assert perf_monitor.collection_interval == 300
    assert len(perf_monitor.metrics_history) == 0
    
    # Test recording metrics
    perf_monitor.record_log_entry()
    perf_monitor.record_log_entry()
    assert perf_monitor.log_entries_counter == 2
    
    perf_monitor.record_threat_analysis_time(25.5)
    assert len(perf_monitor.threat_analysis_times) == 1
    
    perf_monitor.record_event_processing_time(10.2)
    assert len(perf_monitor.event_processing_times) == 1
    
    perf_monitor.record_error()
    assert perf_monitor.error_counter == 1
    
    # Test getting current metrics
    metrics = perf_monitor.get_current_metrics()
    assert isinstance(metrics, PerformanceMetrics)
    assert metrics.cpu_percent >= 0
    assert metrics.memory_percent >= 0
    
    # Test queue tracking
    def mock_queue_size():
        return 42
    
    perf_monitor.register_queue_tracker("test_queue", mock_queue_size)
    metrics = perf_monitor.get_current_metrics()
    assert "test_queue" in metrics.queue_sizes
    assert metrics.queue_sizes["test_queue"] == 42
    
    # Test performance stats (with empty history)
    stats = perf_monitor.get_performance_stats()
    assert stats.total_errors == 1
    
    print("✓ PerformanceMonitor basic test passed")


def test_integration_basic():
    """Test basic integration without background threads."""
    print("Testing basic integration...")
    
    memory_manager = MemoryManager(max_log_entries=50)
    perf_monitor = PerformanceMonitor()
    
    # Add some data
    for i in range(10):
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id=f"session_{i}",
            event_type="command",
            source_ip=f"192.168.1.{i % 3}",
            message=f"test command {i}"
        )
        
        memory_manager.add_log_entry(entry)
        perf_monitor.record_log_entry()
    
    # Check results
    memory_stats = memory_manager.get_memory_stats()
    perf_stats = perf_monitor.get_performance_stats()
    
    assert memory_stats.log_entries_count == 10
    assert perf_monitor.log_entries_counter == 10
    
    print("✓ Basic integration test passed")


def main():
    """Run all basic tests."""
    print("Running basic memory and performance tests...")
    print("=" * 50)
    
    try:
        test_memory_manager_basic()
        test_performance_monitor_basic()
        test_integration_basic()
        
        print("=" * 50)
        print("✓ All basic tests passed!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())