"""
Memory management service for honeypot monitoring.

This module provides memory optimization, cleanup, and monitoring
to prevent memory bloat during long-running operations.
"""

import gc
import threading
import time
import psutil
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass

from ..models.log_entry import LogEntry
from ..models.session import Session
from ..models.threat_assessment import ThreatAssessment
from ..models.irc_alert import IRCAlert


logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics."""
    total_memory_mb: float
    used_memory_mb: float
    available_memory_mb: float
    memory_percent: float
    process_memory_mb: float
    log_entries_count: int
    sessions_count: int
    threats_count: int
    alerts_count: int


class MemoryManager:
    """
    Memory management service for optimizing memory usage.
    
    Features:
    - Memory usage monitoring and reporting
    - Automatic cleanup of old data
    - Memory limits enforcement
    - Background cleanup tasks
    - Memory optimization strategies
    """
    
    def __init__(self,
                 max_log_entries: int = 10000,
                 max_sessions: int = 1000,
                 max_threats: int = 5000,
                 max_alerts: int = 1000,
                 cleanup_interval: int = 300,  # 5 minutes
                 memory_threshold: float = 80.0,  # 80% memory usage
                 enable_gc_optimization: bool = True):
        """
        Initialize the memory manager.
        
        Args:
            max_log_entries: Maximum number of log entries to keep in memory
            max_sessions: Maximum number of sessions to keep in memory
            max_threats: Maximum number of threat assessments to keep
            max_alerts: Maximum number of alerts to keep
            cleanup_interval: Interval between cleanup runs (seconds)
            memory_threshold: Memory usage threshold for aggressive cleanup (%)
            enable_gc_optimization: Whether to enable garbage collection optimization
        """
        self.max_log_entries = max_log_entries
        self.max_sessions = max_sessions
        self.max_threats = max_threats
        self.max_alerts = max_alerts
        self.cleanup_interval = cleanup_interval
        self.memory_threshold = memory_threshold
        self.enable_gc_optimization = enable_gc_optimization
        
        # Data storage with memory limits
        self.log_entries: deque[LogEntry] = deque(maxlen=max_log_entries)
        self.sessions: Dict[str, Session] = {}
        self.threat_assessments: deque[ThreatAssessment] = deque(maxlen=max_threats)
        self.alerts: deque[IRCAlert] = deque(maxlen=max_alerts)
        
        # Cleanup tracking
        self.last_cleanup = datetime.now()
        self.cleanup_stats = {
            'total_cleanups': 0,
            'entries_cleaned': 0,
            'sessions_cleaned': 0,
            'threats_cleaned': 0,
            'alerts_cleaned': 0,
            'memory_freed_mb': 0.0
        }
        
        # Background cleanup
        self.cleanup_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        self.is_running = False
        
        # Memory monitoring
        self.memory_callbacks: List[Callable[[MemoryStats], None]] = []
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Configure garbage collection if enabled
        if self.enable_gc_optimization:
            self._configure_gc()
    
    def start(self) -> None:
        """Start the memory manager background tasks."""
        if self.is_running:
            return
        
        self.is_running = True
        self.shutdown_event.clear()
        
        # Start background cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="MemoryManager-Cleanup",
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info("Memory manager started")
    
    def stop(self) -> None:
        """Stop the memory manager background tasks."""
        if not self.is_running:
            return
        
        self.is_running = False
        self.shutdown_event.set()
        
        # Wait for cleanup thread to finish
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5.0)
        
        logger.info("Memory manager stopped")
    
    def add_log_entry(self, entry: LogEntry) -> None:
        """
        Add a log entry with memory management.
        
        Args:
            entry: LogEntry to add
        """
        with self._lock:
            self.log_entries.append(entry)
            
            # Check if we need immediate cleanup
            if self._should_trigger_cleanup():
                self._perform_cleanup()
    
    def add_session(self, session: Session) -> None:
        """
        Add a session with memory management.
        
        Args:
            session: Session to add
        """
        with self._lock:
            self.sessions[session.session_id] = session
            
            # Enforce session limit
            if len(self.sessions) > self.max_sessions:
                self._cleanup_old_sessions()
    
    def add_threat_assessment(self, threat: ThreatAssessment) -> None:
        """
        Add a threat assessment with memory management.
        
        Args:
            threat: ThreatAssessment to add
        """
        with self._lock:
            self.threat_assessments.append(threat)
    
    def add_alert(self, alert: IRCAlert) -> None:
        """
        Add an alert with memory management.
        
        Args:
            alert: IRCAlert to add
        """
        with self._lock:
            self.alerts.append(alert)
    
    def get_log_entries(self, limit: Optional[int] = None) -> List[LogEntry]:
        """
        Get log entries with optional limit.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of LogEntry objects
        """
        with self._lock:
            entries = list(self.log_entries)
            if limit:
                return entries[-limit:]
            return entries
    
    def get_sessions(self) -> Dict[str, Session]:
        """
        Get all sessions.
        
        Returns:
            Dictionary of sessions
        """
        with self._lock:
            return self.sessions.copy()
    
    def get_threat_assessments(self, limit: Optional[int] = None) -> List[ThreatAssessment]:
        """
        Get threat assessments with optional limit.
        
        Args:
            limit: Maximum number of assessments to return
            
        Returns:
            List of ThreatAssessment objects
        """
        with self._lock:
            assessments = list(self.threat_assessments)
            if limit:
                return assessments[-limit:]
            return assessments
    
    def get_alerts(self, limit: Optional[int] = None) -> List[IRCAlert]:
        """
        Get alerts with optional limit.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of IRCAlert objects
        """
        with self._lock:
            alerts = list(self.alerts)
            if limit:
                return alerts[-limit:]
            return alerts
    
    def get_memory_stats(self) -> MemoryStats:
        """
        Get current memory usage statistics.
        
        Returns:
            MemoryStats object with current usage
        """
        # System memory stats
        memory = psutil.virtual_memory()
        process = psutil.Process()
        process_memory = process.memory_info()
        
        with self._lock:
            return MemoryStats(
                total_memory_mb=memory.total / (1024 * 1024),
                used_memory_mb=memory.used / (1024 * 1024),
                available_memory_mb=memory.available / (1024 * 1024),
                memory_percent=memory.percent,
                process_memory_mb=process_memory.rss / (1024 * 1024),
                log_entries_count=len(self.log_entries),
                sessions_count=len(self.sessions),
                threats_count=len(self.threat_assessments),
                alerts_count=len(self.alerts)
            )
    
    def get_cleanup_stats(self) -> Dict[str, Any]:
        """
        Get cleanup statistics.
        
        Returns:
            Dictionary with cleanup statistics
        """
        return self.cleanup_stats.copy()
    
    def force_cleanup(self) -> Dict[str, int]:
        """
        Force immediate cleanup and return statistics.
        
        Returns:
            Dictionary with cleanup results
        """
        with self._lock:
            return self._perform_cleanup()
    
    def force_gc(self) -> Dict[str, Any]:
        """
        Force garbage collection and return statistics.
        
        Returns:
            Dictionary with GC statistics
        """
        before_stats = self.get_memory_stats()
        
        # Force garbage collection
        collected = gc.collect()
        
        after_stats = self.get_memory_stats()
        
        return {
            'objects_collected': collected,
            'memory_before_mb': before_stats.process_memory_mb,
            'memory_after_mb': after_stats.process_memory_mb,
            'memory_freed_mb': before_stats.process_memory_mb - after_stats.process_memory_mb
        }
    
    def register_memory_callback(self, callback: Callable[[MemoryStats], None]) -> None:
        """
        Register a callback for memory statistics updates.
        
        Args:
            callback: Function to call with MemoryStats
        """
        if callback not in self.memory_callbacks:
            self.memory_callbacks.append(callback)
    
    def unregister_memory_callback(self, callback: Callable[[MemoryStats], None]) -> None:
        """
        Unregister a memory statistics callback.
        
        Args:
            callback: Function to remove from callbacks
        """
        if callback in self.memory_callbacks:
            self.memory_callbacks.remove(callback)
    
    def _configure_gc(self) -> None:
        """Configure garbage collection for optimal performance."""
        # Set GC thresholds for better performance
        # (threshold0, threshold1, threshold2)
        # More aggressive collection for generation 0 (short-lived objects)
        gc.set_threshold(700, 10, 10)
        
        # Enable automatic garbage collection
        gc.enable()
        
        logger.info("Garbage collection configured for optimization")
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while not self.shutdown_event.is_set():
            try:
                # Wait for cleanup interval or shutdown
                if self.shutdown_event.wait(timeout=self.cleanup_interval):
                    break
                
                # Perform periodic cleanup
                with self._lock:
                    self._perform_cleanup()
                
                # Notify memory callbacks
                self._notify_memory_callbacks()
                
                # Force GC if memory usage is high
                memory_stats = self.get_memory_stats()
                if memory_stats.memory_percent > self.memory_threshold:
                    self.force_gc()
                    logger.info(f"Forced GC due to high memory usage: {memory_stats.memory_percent:.1f}%")
                
            except Exception as e:
                logger.error(f"Error in memory cleanup loop: {e}")
    
    def _should_trigger_cleanup(self) -> bool:
        """Check if immediate cleanup should be triggered."""
        # Check time since last cleanup
        time_since_cleanup = datetime.now() - self.last_cleanup
        if time_since_cleanup.total_seconds() > self.cleanup_interval:
            return True
        
        # Check memory usage
        memory_stats = self.get_memory_stats()
        if memory_stats.memory_percent > self.memory_threshold:
            return True
        
        # Check data structure sizes
        if (len(self.log_entries) >= self.max_log_entries * 0.9 or
            len(self.sessions) >= self.max_sessions * 0.9 or
            len(self.threat_assessments) >= self.max_threats * 0.9 or
            len(self.alerts) >= self.max_alerts * 0.9):
            return True
        
        return False
    
    def _perform_cleanup(self) -> Dict[str, int]:
        """
        Perform cleanup of old data.
        
        Returns:
            Dictionary with cleanup statistics
        """
        cleanup_results = {
            'entries_cleaned': 0,
            'sessions_cleaned': 0,
            'threats_cleaned': 0,
            'alerts_cleaned': 0
        }
        
        # Cleanup old sessions
        cleanup_results['sessions_cleaned'] = self._cleanup_old_sessions()
        
        # Cleanup old threat assessments (keep recent ones)
        if len(self.threat_assessments) > self.max_threats * 0.8:
            old_count = len(self.threat_assessments)
            # Keep only the most recent 80% of max
            keep_count = int(self.max_threats * 0.8)
            while len(self.threat_assessments) > keep_count:
                self.threat_assessments.popleft()
            cleanup_results['threats_cleaned'] = old_count - len(self.threat_assessments)
        
        # Cleanup old alerts
        if len(self.alerts) > self.max_alerts * 0.8:
            old_count = len(self.alerts)
            keep_count = int(self.max_alerts * 0.8)
            while len(self.alerts) > keep_count:
                self.alerts.popleft()
            cleanup_results['alerts_cleaned'] = old_count - len(self.alerts)
        
        # Update cleanup stats
        self.cleanup_stats['total_cleanups'] += 1
        self.cleanup_stats['entries_cleaned'] += cleanup_results['entries_cleaned']
        self.cleanup_stats['sessions_cleaned'] += cleanup_results['sessions_cleaned']
        self.cleanup_stats['threats_cleaned'] += cleanup_results['threats_cleaned']
        self.cleanup_stats['alerts_cleaned'] += cleanup_results['alerts_cleaned']
        
        self.last_cleanup = datetime.now()
        
        # Log cleanup if significant
        total_cleaned = sum(cleanup_results.values())
        if total_cleaned > 0:
            logger.info(f"Memory cleanup completed: {cleanup_results}")
        
        return cleanup_results
    
    def _cleanup_old_sessions(self) -> int:
        """
        Cleanup old sessions based on age and activity.
        
        Returns:
            Number of sessions cleaned up
        """
        if len(self.sessions) <= self.max_sessions * 0.8:
            return 0
        
        # Sort sessions by last activity (oldest first)
        cutoff_time = datetime.now() - timedelta(hours=24)  # Keep sessions from last 24 hours
        
        sessions_to_remove = []
        for session_id, session in self.sessions.items():
            # Remove sessions older than cutoff or if we have too many
            if (session.end_time and session.end_time < cutoff_time) or \
               len(self.sessions) - len(sessions_to_remove) > self.max_sessions * 0.8:
                sessions_to_remove.append(session_id)
        
        # Remove old sessions
        for session_id in sessions_to_remove:
            del self.sessions[session_id]
        
        return len(sessions_to_remove)
    
    def _notify_memory_callbacks(self) -> None:
        """Notify all registered memory callbacks."""
        if not self.memory_callbacks:
            return
        
        try:
            memory_stats = self.get_memory_stats()
            for callback in self.memory_callbacks:
                try:
                    callback(memory_stats)
                except Exception as e:
                    logger.error(f"Error in memory callback: {e}")
        except Exception as e:
            logger.error(f"Error getting memory stats for callbacks: {e}")