"""
Performance monitoring service for honeypot monitoring.

This module provides performance metrics collection, analysis,
and optimization recommendations for the monitoring system.
"""

import time
import threading
import psutil
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field
from statistics import mean, median


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics snapshot."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_bytes_sent: float
    network_bytes_recv: float
    thread_count: int
    file_descriptors: int
    
    # Application-specific metrics
    log_entries_per_second: float = 0.0
    threat_analysis_time_ms: float = 0.0
    event_processing_time_ms: float = 0.0
    queue_sizes: Dict[str, int] = field(default_factory=dict)
    error_count: int = 0


@dataclass
class PerformanceStats:
    """Aggregated performance statistics."""
    avg_cpu_percent: float
    max_cpu_percent: float
    avg_memory_percent: float
    max_memory_percent: float
    avg_memory_mb: float
    max_memory_mb: float
    
    avg_log_entries_per_second: float
    max_log_entries_per_second: float
    avg_threat_analysis_time_ms: float
    max_threat_analysis_time_ms: float
    avg_event_processing_time_ms: float
    max_event_processing_time_ms: float
    
    total_errors: int
    uptime_seconds: float
    
    # Performance recommendations
    recommendations: List[str] = field(default_factory=list)


class PerformanceMonitor:
    """
    Performance monitoring service for system optimization.
    
    Features:
    - Real-time performance metrics collection
    - Performance trend analysis
    - Bottleneck detection
    - Optimization recommendations
    - Performance alerts and thresholds
    """
    
    def __init__(self,
                 collection_interval: float = 5.0,
                 history_size: int = 1000,
                 cpu_threshold: float = 80.0,
                 memory_threshold: float = 85.0,
                 enable_detailed_monitoring: bool = True):
        """
        Initialize the performance monitor.
        
        Args:
            collection_interval: Interval between metric collections (seconds)
            history_size: Number of metric snapshots to keep in history
            cpu_threshold: CPU usage threshold for alerts (%)
            memory_threshold: Memory usage threshold for alerts (%)
            enable_detailed_monitoring: Whether to collect detailed app metrics
        """
        self.collection_interval = collection_interval
        self.history_size = history_size
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.enable_detailed_monitoring = enable_detailed_monitoring
        
        # Metrics storage
        self.metrics_history: deque[PerformanceMetrics] = deque(maxlen=history_size)
        self.start_time = datetime.now()
        
        # Application-specific counters
        self.log_entries_counter = 0
        self.threat_analysis_times: deque[float] = deque(maxlen=100)
        self.event_processing_times: deque[float] = deque(maxlen=100)
        self.error_counter = 0
        self.queue_size_trackers: Dict[str, Callable[[], int]] = {}
        
        # Performance tracking
        self.last_metrics_time = time.time()
        self.last_log_entries_count = 0
        
        # Monitoring thread
        self.monitor_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        self.is_running = False
        
        # Callbacks for performance alerts
        self.alert_callbacks: List[Callable[[str, PerformanceMetrics], None]] = []
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize process monitoring
        self.process = psutil.Process()
        self.initial_io_counters = self.process.io_counters()
        self.initial_net_counters = psutil.net_io_counters()
    
    def start(self) -> None:
        """Start performance monitoring."""
        if self.is_running:
            return
        
        self.is_running = True
        self.shutdown_event.clear()
        self.start_time = datetime.now()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            name="PerformanceMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info("Performance monitoring started")
    
    def stop(self) -> None:
        """Stop performance monitoring."""
        if not self.is_running:
            return
        
        self.is_running = False
        self.shutdown_event.set()
        
        # Wait for monitoring thread to finish
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        
        logger.info("Performance monitoring stopped")
    
    def record_log_entry(self) -> None:
        """Record a log entry for throughput calculation."""
        with self._lock:
            self.log_entries_counter += 1
    
    def record_threat_analysis_time(self, time_ms: float) -> None:
        """
        Record threat analysis execution time.
        
        Args:
            time_ms: Analysis time in milliseconds
        """
        with self._lock:
            self.threat_analysis_times.append(time_ms)
    
    def record_event_processing_time(self, time_ms: float) -> None:
        """
        Record event processing time.
        
        Args:
            time_ms: Processing time in milliseconds
        """
        with self._lock:
            self.event_processing_times.append(time_ms)
    
    def record_error(self) -> None:
        """Record an error occurrence."""
        with self._lock:
            self.error_counter += 1
    
    def register_queue_tracker(self, name: str, size_func: Callable[[], int]) -> None:
        """
        Register a queue size tracker.
        
        Args:
            name: Name of the queue
            size_func: Function that returns current queue size
        """
        self.queue_size_trackers[name] = size_func
    
    def register_alert_callback(self, callback: Callable[[str, PerformanceMetrics], None]) -> None:
        """
        Register a callback for performance alerts.
        
        Args:
            callback: Function to call when performance thresholds are exceeded
        """
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """
        Get current performance metrics.
        
        Returns:
            PerformanceMetrics object with current values
        """
        return self._collect_metrics()
    
    def get_performance_stats(self, duration_minutes: Optional[int] = None) -> PerformanceStats:
        """
        Get aggregated performance statistics.
        
        Args:
            duration_minutes: Duration to analyze (None for all history)
            
        Returns:
            PerformanceStats object with aggregated data
        """
        with self._lock:
            metrics_list = list(self.metrics_history)
        
        if not metrics_list:
            return self._empty_stats()
        
        # Filter by duration if specified
        if duration_minutes:
            cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
            metrics_list = [m for m in metrics_list if m.timestamp > cutoff_time]
        
        if not metrics_list:
            return self._empty_stats()
        
        # Calculate statistics
        cpu_values = [m.cpu_percent for m in metrics_list]
        memory_percent_values = [m.memory_percent for m in metrics_list]
        memory_mb_values = [m.memory_mb for m in metrics_list]
        log_rate_values = [m.log_entries_per_second for m in metrics_list if m.log_entries_per_second > 0]
        threat_time_values = [m.threat_analysis_time_ms for m in metrics_list if m.threat_analysis_time_ms > 0]
        event_time_values = [m.event_processing_time_ms for m in metrics_list if m.event_processing_time_ms > 0]
        
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        stats = PerformanceStats(
            avg_cpu_percent=mean(cpu_values) if cpu_values else 0.0,
            max_cpu_percent=max(cpu_values) if cpu_values else 0.0,
            avg_memory_percent=mean(memory_percent_values) if memory_percent_values else 0.0,
            max_memory_percent=max(memory_percent_values) if memory_percent_values else 0.0,
            avg_memory_mb=mean(memory_mb_values) if memory_mb_values else 0.0,
            max_memory_mb=max(memory_mb_values) if memory_mb_values else 0.0,
            avg_log_entries_per_second=mean(log_rate_values) if log_rate_values else 0.0,
            max_log_entries_per_second=max(log_rate_values) if log_rate_values else 0.0,
            avg_threat_analysis_time_ms=mean(threat_time_values) if threat_time_values else 0.0,
            max_threat_analysis_time_ms=max(threat_time_values) if threat_time_values else 0.0,
            avg_event_processing_time_ms=mean(event_time_values) if event_time_values else 0.0,
            max_event_processing_time_ms=max(event_time_values) if event_time_values else 0.0,
            total_errors=self.error_counter,
            uptime_seconds=uptime
        )
        
        # Generate recommendations
        stats.recommendations = self._generate_recommendations(stats)
        
        return stats
    
    def get_metrics_history(self, duration_minutes: Optional[int] = None) -> List[PerformanceMetrics]:
        """
        Get metrics history.
        
        Args:
            duration_minutes: Duration to retrieve (None for all history)
            
        Returns:
            List of PerformanceMetrics objects
        """
        with self._lock:
            metrics_list = list(self.metrics_history)
        
        if duration_minutes:
            cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
            metrics_list = [m for m in metrics_list if m.timestamp > cutoff_time]
        
        return metrics_list
    
    def get_bottlenecks(self) -> List[Dict[str, Any]]:
        """
        Identify performance bottlenecks.
        
        Returns:
            List of bottleneck descriptions
        """
        bottlenecks = []
        stats = self.get_performance_stats(duration_minutes=30)  # Last 30 minutes
        
        # CPU bottleneck
        if stats.avg_cpu_percent > self.cpu_threshold:
            bottlenecks.append({
                'type': 'cpu',
                'severity': 'high' if stats.avg_cpu_percent > 90 else 'medium',
                'description': f'High CPU usage: {stats.avg_cpu_percent:.1f}% average',
                'recommendation': 'Consider optimizing processing algorithms or reducing processing frequency'
            })
        
        # Memory bottleneck
        if stats.avg_memory_percent > self.memory_threshold:
            bottlenecks.append({
                'type': 'memory',
                'severity': 'high' if stats.avg_memory_percent > 95 else 'medium',
                'description': f'High memory usage: {stats.avg_memory_percent:.1f}% average',
                'recommendation': 'Enable more aggressive memory cleanup or reduce data retention'
            })
        
        # Slow threat analysis
        if stats.avg_threat_analysis_time_ms > 100:
            bottlenecks.append({
                'type': 'threat_analysis',
                'severity': 'medium',
                'description': f'Slow threat analysis: {stats.avg_threat_analysis_time_ms:.1f}ms average',
                'recommendation': 'Optimize threat detection rules or implement caching'
            })
        
        # Slow event processing
        if stats.avg_event_processing_time_ms > 50:
            bottlenecks.append({
                'type': 'event_processing',
                'severity': 'medium',
                'description': f'Slow event processing: {stats.avg_event_processing_time_ms:.1f}ms average',
                'recommendation': 'Optimize event handlers or increase worker threads'
            })
        
        # High error rate
        error_rate = stats.total_errors / max(stats.uptime_seconds / 60, 1)  # errors per minute
        if error_rate > 1.0:
            bottlenecks.append({
                'type': 'errors',
                'severity': 'high' if error_rate > 5.0 else 'medium',
                'description': f'High error rate: {error_rate:.1f} errors per minute',
                'recommendation': 'Investigate and fix recurring errors'
            })
        
        return bottlenecks
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while not self.shutdown_event.is_set():
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                
                # Store in history
                with self._lock:
                    self.metrics_history.append(metrics)
                
                # Check for performance alerts
                self._check_performance_alerts(metrics)
                
                # Wait for next collection
                if self.shutdown_event.wait(timeout=self.collection_interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                self.record_error()
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics."""
        current_time = time.time()
        
        # System metrics
        cpu_percent = self.process.cpu_percent()
        memory_info = self.process.memory_info()
        memory_percent = self.process.memory_percent()
        
        # I/O metrics
        try:
            io_counters = self.process.io_counters()
            disk_read_mb = (io_counters.read_bytes - self.initial_io_counters.read_bytes) / (1024 * 1024)
            disk_write_mb = (io_counters.write_bytes - self.initial_io_counters.write_bytes) / (1024 * 1024)
        except (AttributeError, psutil.AccessDenied):
            disk_read_mb = disk_write_mb = 0.0
        
        # Network metrics
        try:
            net_counters = psutil.net_io_counters()
            if net_counters and self.initial_net_counters:
                net_sent = net_counters.bytes_sent - self.initial_net_counters.bytes_sent
                net_recv = net_counters.bytes_recv - self.initial_net_counters.bytes_recv
            else:
                net_sent = net_recv = 0.0
        except (AttributeError, psutil.AccessDenied):
            net_sent = net_recv = 0.0
        
        # Process metrics
        try:
            thread_count = self.process.num_threads()
            fd_count = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
        except (AttributeError, psutil.AccessDenied):
            thread_count = fd_count = 0
        
        # Application-specific metrics
        with self._lock:
            # Calculate log entries per second
            time_delta = current_time - self.last_metrics_time
            entries_delta = self.log_entries_counter - self.last_log_entries_count
            log_entries_per_second = entries_delta / max(time_delta, 0.1)
            
            # Update counters
            self.last_metrics_time = current_time
            self.last_log_entries_count = self.log_entries_counter
            
            # Get average processing times
            threat_analysis_time = mean(self.threat_analysis_times) if self.threat_analysis_times else 0.0
            event_processing_time = mean(self.event_processing_times) if self.event_processing_times else 0.0
            
            # Get queue sizes
            queue_sizes = {}
            for name, size_func in self.queue_size_trackers.items():
                try:
                    queue_sizes[name] = size_func()
                except Exception as e:
                    logger.warning(f"Failed to get queue size for {name}: {e}")
                    queue_sizes[name] = 0
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_mb=memory_info.rss / (1024 * 1024),
            disk_io_read_mb=disk_read_mb,
            disk_io_write_mb=disk_write_mb,
            network_bytes_sent=net_sent,
            network_bytes_recv=net_recv,
            thread_count=thread_count,
            file_descriptors=fd_count,
            log_entries_per_second=log_entries_per_second,
            threat_analysis_time_ms=threat_analysis_time,
            event_processing_time_ms=event_processing_time,
            queue_sizes=queue_sizes,
            error_count=self.error_counter
        )
    
    def _check_performance_alerts(self, metrics: PerformanceMetrics) -> None:
        """Check for performance threshold violations and trigger alerts."""
        alerts = []
        
        # CPU alert
        if metrics.cpu_percent > self.cpu_threshold:
            alerts.append(f"High CPU usage: {metrics.cpu_percent:.1f}%")
        
        # Memory alert
        if metrics.memory_percent > self.memory_threshold:
            alerts.append(f"High memory usage: {metrics.memory_percent:.1f}%")
        
        # Queue size alerts
        for queue_name, size in metrics.queue_sizes.items():
            if size > 1000:  # Arbitrary threshold
                alerts.append(f"Large queue size: {queue_name} has {size} items")
        
        # Trigger callbacks for each alert
        for alert_message in alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(alert_message, metrics)
                except Exception as e:
                    logger.error(f"Error in performance alert callback: {e}")
    
    def _generate_recommendations(self, stats: PerformanceStats) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # CPU recommendations
        if stats.avg_cpu_percent > 70:
            recommendations.append("Consider reducing log processing frequency or optimizing algorithms")
        
        # Memory recommendations
        if stats.avg_memory_percent > 80:
            recommendations.append("Enable more aggressive memory cleanup or reduce data retention periods")
        
        # Processing time recommendations
        if stats.avg_threat_analysis_time_ms > 50:
            recommendations.append("Optimize threat detection rules or implement result caching")
        
        if stats.avg_event_processing_time_ms > 25:
            recommendations.append("Optimize event handlers or increase worker thread count")
        
        # Error rate recommendations
        error_rate = stats.total_errors / max(stats.uptime_seconds / 60, 1)
        if error_rate > 0.5:
            recommendations.append("Investigate and resolve recurring errors to improve stability")
        
        # Throughput recommendations
        if stats.max_log_entries_per_second > 100:
            recommendations.append("Consider implementing batching for high-throughput scenarios")
        
        return recommendations
    
    def _empty_stats(self) -> PerformanceStats:
        """Return empty performance stats."""
        return PerformanceStats(
            avg_cpu_percent=0.0,
            max_cpu_percent=0.0,
            avg_memory_percent=0.0,
            max_memory_percent=0.0,
            avg_memory_mb=0.0,
            max_memory_mb=0.0,
            avg_log_entries_per_second=0.0,
            max_log_entries_per_second=0.0,
            avg_threat_analysis_time_ms=0.0,
            max_threat_analysis_time_ms=0.0,
            avg_event_processing_time_ms=0.0,
            max_event_processing_time_ms=0.0,
            total_errors=0,
            uptime_seconds=0.0
        )