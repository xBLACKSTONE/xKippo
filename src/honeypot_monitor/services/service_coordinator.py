"""
Service coordinator for managing all honeypot monitoring services.

This module coordinates the log monitor, threat analyzer, IRC notifier,
alert manager, and event system to provide integrated monitoring.
"""

import logging
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from ..config.settings import Settings
from ..models.log_entry import LogEntry
from ..models.threat_assessment import ThreatAssessment
from ..models.irc_alert import IRCAlert
from .event_manager import EventManager, EventType, Event
from .log_monitor import LogMonitor
from .log_parser import KippoLogParser
from .threat_analyzer import ThreatAnalyzer
from .irc_notifier import IRCNotifier
from .alert_manager import AlertManager
from .memory_manager import MemoryManager
from .performance_monitor import PerformanceMonitor


logger = logging.getLogger(__name__)


class ServiceCoordinator:
    """
    Coordinates all monitoring services and provides unified interface.
    
    Manages service lifecycle, error handling, and event-driven communication
    between components.
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize the service coordinator.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.is_running = False
        self._lock = threading.Lock()
        
        # Initialize event manager first
        self.event_manager = EventManager()
        
        # Initialize services
        self.log_parser: Optional[KippoLogParser] = None
        self.log_monitor: Optional[LogMonitor] = None
        self.threat_analyzer: Optional[ThreatAnalyzer] = None
        self.irc_notifier: Optional[IRCNotifier] = None
        self.alert_manager: Optional[AlertManager] = None
        self.memory_manager: Optional[MemoryManager] = None
        self.performance_monitor: Optional[PerformanceMonitor] = None
        
        # Service state tracking
        self.service_states = {
            'log_monitor': 'stopped',
            'threat_analyzer': 'stopped',
            'irc_notifier': 'stopped',
            'alert_manager': 'stopped',
            'memory_manager': 'stopped',
            'performance_monitor': 'stopped'
        }
        
        # Error tracking
        self.service_errors: Dict[str, List[str]] = {
            'log_monitor': [],
            'threat_analyzer': [],
            'irc_notifier': [],
            'alert_manager': [],
            'memory_manager': [],
            'performance_monitor': []
        }
        
        # Initialize services
        self._initialize_services()
        self._setup_event_subscriptions()
    
    def start(self) -> bool:
        """
        Start all monitoring services.
        
        Returns:
            True if all services started successfully, False otherwise
        """
        print("DEBUG: ServiceCoordinator.start() called")  # Debug output
        with self._lock:
            print("DEBUG: Acquired lock")  # Debug output
            if self.is_running:
                print("DEBUG: Services already running")  # Debug output
                logger.warning("Services already running")
                return True
            
            print("DEBUG: About to start honeypot monitoring services")  # Debug output
            logger.info("Starting honeypot monitoring services")
            print("DEBUG: Logger message sent")  # Debug output
            
            try:
                # Start log monitoring
                print("DEBUG: Starting log monitoring...")  # Debug output
                if not self._start_log_monitoring():
                    print("DEBUG: Log monitoring failed to start!")  # Debug output
                    return False
                print("DEBUG: Log monitoring started successfully")  # Debug output
                
                # Start threat analysis
                print("DEBUG: Starting threat analysis...")  # Debug output
                if not self._start_threat_analysis():
                    print("DEBUG: Threat analysis failed to start!")  # Debug output
                    return False
                print("DEBUG: Threat analysis started successfully")  # Debug output
                
                # Start IRC notifications (optional)
                print("DEBUG: Starting IRC notifications...")  # Debug output
                self._start_irc_notifications()
                print("DEBUG: IRC notifications started")  # Debug output
                
                # Start alert management
                print("DEBUG: Starting alert management...")  # Debug output
                if not self._start_alert_management():
                    print("DEBUG: Alert management failed to start!")  # Debug output
                    return False
                print("DEBUG: Alert management started successfully")  # Debug output
                
                # Start memory management
                print("DEBUG: Starting memory management...")  # Debug output
                if not self._start_memory_management():
                    print("DEBUG: Memory management failed to start!")  # Debug output
                    return False
                print("DEBUG: Memory management started successfully")  # Debug output
                
                # Start performance monitoring
                print("DEBUG: Starting performance monitoring...")  # Debug output
                if not self._start_performance_monitoring():
                    print("DEBUG: Performance monitoring failed to start!")  # Debug output
                    return False
                print("DEBUG: Performance monitoring started successfully")  # Debug output
                
                self.is_running = True
                self.event_manager.publish_monitoring_status("started", "All services started")
                logger.info("All monitoring services started successfully")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start services: {e}")
                self.event_manager.publish_system_error(f"Service startup failed: {e}", e)
                self.stop()
                return False
    
    def stop(self) -> None:
        """Stop all monitoring services."""
        with self._lock:
            if not self.is_running:
                return
            
            logger.info("Stopping honeypot monitoring services")
            
            # Stop services in reverse order
            self._stop_performance_monitoring()
            self._stop_memory_management()
            self._stop_alert_management()
            self._stop_irc_notifications()
            self._stop_threat_analysis()
            self._stop_log_monitoring()
            
            self.is_running = False
            self.event_manager.publish_monitoring_status("stopped", "All services stopped")
            logger.info("All monitoring services stopped")
    
    def shutdown(self) -> None:
        """Shutdown coordinator and cleanup resources."""
        self.stop()
        self.event_manager.shutdown()
        logger.info("Service coordinator shutdown complete")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all services.
        
        Returns:
            Dictionary with service status information
        """
        status = {
            'is_running': self.is_running,
            'services': self.service_states.copy(),
            'errors': {k: v.copy() for k, v in self.service_errors.items()},
            'event_manager': self.event_manager.get_statistics()
        }
        
        # Add detailed service status
        if self.log_monitor:
            status['log_monitor_details'] = self.log_monitor.get_monitoring_status()
        
        if self.irc_notifier:
            status['irc_details'] = self.irc_notifier.get_connection_status()
        
        if self.alert_manager:
            status['alert_statistics'] = self.alert_manager.get_alert_statistics()
        
        if self.memory_manager:
            status['memory_stats'] = {
                'memory_usage': self.memory_manager.get_memory_stats().__dict__,
                'cleanup_stats': self.memory_manager.get_cleanup_stats()
            }
        
        if self.performance_monitor:
            status['performance_stats'] = self.performance_monitor.get_performance_stats().__dict__
            status['bottlenecks'] = self.performance_monitor.get_bottlenecks()
        
        return status
    
    def get_recent_entries(self, count: int = 100) -> List[LogEntry]:
        """
        Get recent log entries.
        
        Args:
            count: Number of entries to retrieve
            
        Returns:
            List of recent LogEntry objects
        """
        # Prefer memory manager for better performance and memory management
        if self.memory_manager:
            return self.memory_manager.get_log_entries(limit=count)
        elif self.log_monitor:
            return self.log_monitor.get_recent_entries(count)
        return []
    
    def force_pattern_analysis(self) -> List[Dict[str, Any]]:
        """
        Force pattern analysis on recent entries.
        
        Returns:
            List of detected patterns
        """
        if not self.threat_analyzer or not self.log_monitor:
            return []
        
        recent_entries = self.log_monitor.get_recent_entries(1000)
        patterns = self.threat_analyzer.detect_patterns(recent_entries)
        
        # Publish pattern events
        for pattern in patterns:
            self.event_manager.publish_pattern_detected(pattern)
        
        return patterns
    
    def test_irc_connection(self) -> bool:
        """
        Test IRC connection.
        
        Returns:
            True if IRC is connected, False otherwise
        """
        if self.irc_notifier:
            return self.irc_notifier.is_connected()
        return False
    
    def send_test_alert(self, message: str = "Test alert from honeypot monitor") -> bool:
        """
        Send a test IRC alert.
        
        Args:
            message: Test message to send
            
        Returns:
            True if alert sent successfully
        """
        if self.irc_notifier and self.irc_notifier.is_connected():
            return self.irc_notifier.send_message(f"[TEST] {message}")
        return False
    
    def get_memory_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Get detailed memory statistics.
        
        Returns:
            Dictionary with memory statistics or None if not available
        """
        if self.memory_manager:
            memory_stats = self.memory_manager.get_memory_stats()
            cleanup_stats = self.memory_manager.get_cleanup_stats()
            
            return {
                'memory_usage': memory_stats.__dict__,
                'cleanup_statistics': cleanup_stats,
                'data_counts': {
                    'log_entries': len(self.memory_manager.log_entries),
                    'sessions': len(self.memory_manager.sessions),
                    'threat_assessments': len(self.memory_manager.threat_assessments),
                    'alerts': len(self.memory_manager.alerts)
                }
            }
        return None
    
    def get_performance_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Get detailed performance statistics.
        
        Returns:
            Dictionary with performance statistics or None if not available
        """
        if self.performance_monitor:
            current_metrics = self.performance_monitor.get_current_metrics()
            performance_stats = self.performance_monitor.get_performance_stats()
            bottlenecks = self.performance_monitor.get_bottlenecks()
            
            return {
                'current_metrics': current_metrics.__dict__,
                'performance_stats': performance_stats.__dict__,
                'bottlenecks': bottlenecks,
                'metrics_history_count': len(self.performance_monitor.get_metrics_history())
            }
        return None
    
    def force_memory_cleanup(self) -> Optional[Dict[str, int]]:
        """
        Force immediate memory cleanup.
        
        Returns:
            Cleanup results or None if not available
        """
        if self.memory_manager:
            return self.memory_manager.force_cleanup()
        return None
    
    def force_garbage_collection(self) -> Optional[Dict[str, Any]]:
        """
        Force garbage collection.
        
        Returns:
            GC results or None if not available
        """
        if self.memory_manager:
            return self.memory_manager.force_gc()
        return None
    
    def _initialize_services(self) -> None:
        """Initialize all service instances."""
        try:
            # Initialize log parser
            self.log_parser = KippoLogParser()
            
            # Initialize log monitor
            self.log_monitor = LogMonitor(
                parser=self.log_parser,
                buffer_size=self.settings.monitoring.max_entries_memory,
                batch_size=100
            )
            
            # Initialize threat analyzer
            self.threat_analyzer = ThreatAnalyzer(self.settings.analysis)
            
            # Initialize IRC notifier if enabled
            if self.settings.irc.enabled:
                self.irc_notifier = IRCNotifier(
                    server=self.settings.irc.server,
                    port=self.settings.irc.port,
                    nickname=self.settings.irc.nickname,
                    channel=self.settings.irc.channel,
                    use_ssl=self.settings.irc.ssl
                )
            
            # Initialize alert manager
            self.alert_manager = AlertManager(
                threat_analyzer=self.threat_analyzer,
                irc_notifier=self.irc_notifier,
                alert_threshold=self.settings.analysis.threat_threshold
            )
            
            # Initialize memory manager
            self.memory_manager = MemoryManager(
                max_log_entries=self.settings.monitoring.max_entries_memory,
                max_sessions=1000,
                max_threats=5000,
                max_alerts=1000,
                cleanup_interval=300,  # 5 minutes
                memory_threshold=80.0,
                enable_gc_optimization=True
            )
            
            # Initialize performance monitor
            self.performance_monitor = PerformanceMonitor(
                collection_interval=5.0,
                history_size=1000,
                cpu_threshold=80.0,
                memory_threshold=85.0,
                enable_detailed_monitoring=True
            )
            
            logger.info("All services initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize services: {e}")
            raise
    
    def _setup_event_subscriptions(self) -> None:
        """Setup event subscriptions for service coordination."""
        # Subscribe to log entries for threat analysis
        self.event_manager.subscribe(EventType.LOG_ENTRY, self._handle_log_entry)
        
        # Subscribe to threat detection for alerts
        self.event_manager.subscribe(EventType.THREAT_DETECTED, self._handle_threat_detected)
        
        # Subscribe to IRC status changes
        self.event_manager.subscribe(EventType.IRC_CONNECTED, self._handle_irc_connected)
        self.event_manager.subscribe(EventType.IRC_DISCONNECTED, self._handle_irc_disconnected)
        self.event_manager.subscribe(EventType.IRC_ERROR, self._handle_irc_error)
        
        # Subscribe to monitoring status changes
        self.event_manager.subscribe(EventType.MONITORING_ERROR, self._handle_monitoring_error)
        
        # Subscribe to system errors
        self.event_manager.subscribe(EventType.SYSTEM_ERROR, self._handle_system_error)
    
    def _start_log_monitoring(self) -> bool:
        """Start log monitoring service."""
        try:
            print("DEBUG: Checking log monitor initialization...")  # Debug output
            if not self.log_monitor:
                print("DEBUG: Log monitor not initialized!")  # Debug output
                raise RuntimeError("Log monitor not initialized")
            print("DEBUG: Log monitor is initialized")  # Debug output
            
            # Register callback for new log entries
            print("DEBUG: Registering callback...")  # Debug output
            self.log_monitor.register_callback(self._on_new_log_entry)
            print("DEBUG: Callback registered")  # Debug output
            
            # Start monitoring
            print(f"DEBUG: Starting monitoring of: {self.settings.honeypot.log_path}")  # Debug output
            self.log_monitor.start_monitoring(self.settings.honeypot.log_path)
            print("DEBUG: Log monitoring start_monitoring() completed")  # Debug output
            
            self.service_states['log_monitor'] = 'running'
            logger.info("Log monitoring started")
            return True
            
        except Exception as e:
            error_msg = f"Failed to start log monitoring: {e}"
            logger.error(error_msg)
            self.service_errors['log_monitor'].append(error_msg)
            self.service_states['log_monitor'] = 'error'
            self.event_manager.publish_monitoring_status("error", error_msg)
            return False
    
    def _start_threat_analysis(self) -> bool:
        """Start threat analysis service."""
        try:
            if not self.threat_analyzer:
                raise RuntimeError("Threat analyzer not initialized")
            
            self.service_states['threat_analyzer'] = 'running'
            logger.info("Threat analysis started")
            return True
            
        except Exception as e:
            error_msg = f"Failed to start threat analysis: {e}"
            logger.error(error_msg)
            self.service_errors['threat_analyzer'].append(error_msg)
            self.service_states['threat_analyzer'] = 'error'
            return False
    
    def _start_irc_notifications(self) -> bool:
        """Start IRC notification service."""
        if not self.irc_notifier:
            logger.info("IRC notifications disabled")
            return True
        
        try:
            # Set up IRC callbacks
            self.irc_notifier.set_callbacks(
                on_connect=lambda: self.event_manager.publish_irc_status("connected"),
                on_disconnect=lambda: self.event_manager.publish_irc_status("disconnected"),
                on_error=lambda msg: self.event_manager.publish_irc_status("error", msg)
            )
            
            # Connect to IRC
            if self.irc_notifier.connect():
                self.service_states['irc_notifier'] = 'connecting'
                logger.info("IRC connection initiated")
                return True
            else:
                self.service_states['irc_notifier'] = 'error'
                return False
                
        except Exception as e:
            error_msg = f"Failed to start IRC notifications: {e}"
            logger.error(error_msg)
            self.service_errors['irc_notifier'].append(error_msg)
            self.service_states['irc_notifier'] = 'error'
            return False
    
    def _start_alert_management(self) -> bool:
        """Start alert management service."""
        try:
            if not self.alert_manager:
                raise RuntimeError("Alert manager not initialized")
            
            # Set up alert callbacks
            self.alert_manager.set_callbacks(
                on_new_host=self._on_new_host_detected,
                on_threat=self._on_threat_detected,
                on_interesting_traffic=self._on_interesting_traffic
            )
            
            self.service_states['alert_manager'] = 'running'
            logger.info("Alert management started")
            return True
            
        except Exception as e:
            error_msg = f"Failed to start alert management: {e}"
            logger.error(error_msg)
            self.service_errors['alert_manager'].append(error_msg)
            self.service_states['alert_manager'] = 'error'
            return False
    
    def _stop_log_monitoring(self) -> None:
        """Stop log monitoring service."""
        if self.log_monitor:
            try:
                self.log_monitor.stop_monitoring()
                self.service_states['log_monitor'] = 'stopped'
                logger.info("Log monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping log monitoring: {e}")
    
    def _stop_threat_analysis(self) -> None:
        """Stop threat analysis service."""
        if self.threat_analyzer:
            self.service_states['threat_analyzer'] = 'stopped'
            logger.info("Threat analysis stopped")
    
    def _stop_irc_notifications(self) -> None:
        """Stop IRC notification service."""
        if self.irc_notifier:
            try:
                self.irc_notifier.disconnect()
                self.service_states['irc_notifier'] = 'stopped'
                logger.info("IRC notifications stopped")
            except Exception as e:
                logger.error(f"Error stopping IRC notifications: {e}")
    
    def _stop_alert_management(self) -> None:
        """Stop alert management service."""
        if self.alert_manager:
            self.service_states['alert_manager'] = 'stopped'
            logger.info("Alert management stopped")
    
    def _start_memory_management(self) -> bool:
        """Start memory management service."""
        try:
            if not self.memory_manager:
                raise RuntimeError("Memory manager not initialized")
            
            # Set up performance tracking integration
            if self.performance_monitor:
                self.performance_monitor.register_queue_tracker(
                    "memory_log_entries",
                    lambda: len(self.memory_manager.log_entries)
                )
                self.performance_monitor.register_queue_tracker(
                    "memory_sessions",
                    lambda: len(self.memory_manager.sessions)
                )
            
            self.memory_manager.start()
            self.service_states['memory_manager'] = 'running'
            logger.info("Memory management started")
            return True
            
        except Exception as e:
            error_msg = f"Failed to start memory management: {e}"
            logger.error(error_msg)
            self.service_errors['memory_manager'].append(error_msg)
            self.service_states['memory_manager'] = 'error'
            return False
    
    def _stop_memory_management(self) -> None:
        """Stop memory management service."""
        if self.memory_manager:
            try:
                self.memory_manager.stop()
                self.service_states['memory_manager'] = 'stopped'
                logger.info("Memory management stopped")
            except Exception as e:
                logger.error(f"Error stopping memory management: {e}")
    
    def _start_performance_monitoring(self) -> bool:
        """Start performance monitoring service."""
        try:
            if not self.performance_monitor:
                raise RuntimeError("Performance monitor not initialized")
            
            # Set up performance alert callbacks
            self.performance_monitor.register_alert_callback(self._handle_performance_alert)
            
            # Register queue trackers for event manager
            if hasattr(self.event_manager, 'event_queue'):
                self.performance_monitor.register_queue_tracker(
                    "event_queue",
                    lambda: self.event_manager.event_queue.qsize()
                )
            
            self.performance_monitor.start()
            self.service_states['performance_monitor'] = 'running'
            logger.info("Performance monitoring started")
            return True
            
        except Exception as e:
            error_msg = f"Failed to start performance monitoring: {e}"
            logger.error(error_msg)
            self.service_errors['performance_monitor'].append(error_msg)
            self.service_states['performance_monitor'] = 'error'
            return False
    
    def _stop_performance_monitoring(self) -> None:
        """Stop performance monitoring service."""
        if self.performance_monitor:
            try:
                self.performance_monitor.stop()
                self.service_states['performance_monitor'] = 'stopped'
                logger.info("Performance monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping performance monitoring: {e}")
    
    def _handle_performance_alert(self, alert_message: str, metrics) -> None:
        """Handle performance alerts."""
        logger.warning(f"Performance alert: {alert_message}")
        self.event_manager.publish_system_error(f"Performance alert: {alert_message}")
    
    def _on_new_log_entry(self, log_entry: LogEntry) -> None:
        """Handle new log entry from log monitor."""
        try:
            # Record performance metrics
            if self.performance_monitor:
                self.performance_monitor.record_log_entry()
            
            # Store in memory manager
            if self.memory_manager:
                self.memory_manager.add_log_entry(log_entry)
            
            # Publish log entry event
            self.event_manager.publish_log_entry(log_entry, "log_monitor")
            
        except Exception as e:
            logger.error(f"Error handling new log entry: {e}")
            if self.performance_monitor:
                self.performance_monitor.record_error()
            self.event_manager.publish_system_error(f"Log entry processing error: {e}", e)
    
    def _on_new_host_detected(self, source_ip: str, first_seen: datetime) -> None:
        """Handle new host detection."""
        self.event_manager.publish_new_host(source_ip, first_seen, "alert_manager")
    
    def _on_threat_detected(self, threat: ThreatAssessment, source_ip: str) -> None:
        """Handle threat detection."""
        # This will be called by alert manager, we don't need to republish
        pass
    
    def _on_interesting_traffic(self, source_ip: str, description: str) -> None:
        """Handle interesting traffic detection."""
        # Publish as a generic event for TUI updates
        self.event_manager.publish(
            EventType.PATTERN_DETECTED,
            {
                "pattern": {
                    "type": "interesting_traffic",
                    "source_ip": source_ip,
                    "description": description,
                    "severity": "low"
                }
            },
            "alert_manager"
        )
    
    def _handle_log_entry(self, event: Event) -> None:
        """Handle log entry events for threat analysis and alerting."""
        start_time = time.time()
        
        try:
            log_entry = event.data["log_entry"]
            
            if self.alert_manager:
                # Process through alert manager (which handles threat analysis)
                threat_start_time = time.time()
                alerts = self.alert_manager.process_log_entry(log_entry)
                threat_time_ms = (time.time() - threat_start_time) * 1000
                
                # Record threat analysis performance
                if self.performance_monitor:
                    self.performance_monitor.record_threat_analysis_time(threat_time_ms)
                
                # Store alerts in memory manager
                if self.memory_manager:
                    for alert in alerts:
                        self.memory_manager.add_alert(alert)
                
                # Publish alert events
                for alert in alerts:
                    self.event_manager.publish_alert_sent(alert, True, "alert_manager")
            
            # Record event processing time
            if self.performance_monitor:
                processing_time_ms = (time.time() - start_time) * 1000
                self.performance_monitor.record_event_processing_time(processing_time_ms)
            
        except Exception as e:
            logger.error(f"Error processing log entry event: {e}")
            if self.performance_monitor:
                self.performance_monitor.record_error()
            self.event_manager.publish_system_error(f"Log entry event processing error: {e}", e)
    
    def _handle_threat_detected(self, event: Event) -> None:
        """Handle threat detection events."""
        # This is mainly for logging and statistics
        threat = event.data["threat"]
        source_ip = event.data["source_ip"]
        logger.info(f"Threat detected from {source_ip}: {threat.severity} {threat.category}")
    
    def _handle_irc_connected(self, event: Event) -> None:
        """Handle IRC connection events."""
        self.service_states['irc_notifier'] = 'connected'
        logger.info("IRC connected successfully")
    
    def _handle_irc_disconnected(self, event: Event) -> None:
        """Handle IRC disconnection events."""
        self.service_states['irc_notifier'] = 'disconnected'
        logger.warning("IRC disconnected")
    
    def _handle_irc_error(self, event: Event) -> None:
        """Handle IRC error events."""
        error_msg = event.data.get("message", "Unknown IRC error")
        self.service_errors['irc_notifier'].append(error_msg)
        self.service_states['irc_notifier'] = 'error'
        logger.error(f"IRC error: {error_msg}")
    
    def _handle_monitoring_error(self, event: Event) -> None:
        """Handle monitoring error events."""
        error_msg = event.data.get("message", "Unknown monitoring error")
        self.service_errors['log_monitor'].append(error_msg)
        logger.error(f"Monitoring error: {error_msg}")
    
    def _handle_system_error(self, event: Event) -> None:
        """Handle system error events."""
        error_msg = event.data.get("error_message", "Unknown system error")
        exception = event.data.get("exception")
        logger.error(f"System error: {error_msg}")
        
        # Attempt recovery based on error type
        if "log monitoring" in error_msg.lower():
            self._attempt_log_monitor_recovery()
        elif "irc" in error_msg.lower():
            self._attempt_irc_recovery()
    
    def _attempt_log_monitor_recovery(self) -> None:
        """Attempt to recover log monitoring after error."""
        try:
            if self.log_monitor and not self.log_monitor.is_monitoring:
                logger.info("Attempting to restart log monitoring")
                self.log_monitor.start_monitoring(self.settings.honeypot.log_path)
                self.service_states['log_monitor'] = 'running'
                logger.info("Log monitoring recovery successful")
        except Exception as e:
            logger.error(f"Log monitoring recovery failed: {e}")
            self.service_states['log_monitor'] = 'error'
    
    def _attempt_irc_recovery(self) -> None:
        """Attempt to recover IRC connection after error."""
        try:
            if self.irc_notifier and not self.irc_notifier.is_connected():
                logger.info("Attempting to reconnect IRC")
                self.irc_notifier.connect()
                logger.info("IRC recovery attempt initiated")
        except Exception as e:
            logger.error(f"IRC recovery failed: {e}")
            self.service_states['irc_notifier'] = 'error'