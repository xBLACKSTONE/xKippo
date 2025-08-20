"""
Event-driven architecture manager for honeypot monitoring.

This module provides a central event system that coordinates between
log monitoring, threat analysis, IRC notifications, and TUI updates.
"""

import logging
import threading
from typing import Dict, List, Callable, Any, Optional
from datetime import datetime
from queue import Queue, Empty
from dataclasses import dataclass
from enum import Enum

from ..models.log_entry import LogEntry
from ..models.threat_assessment import ThreatAssessment
from ..models.irc_alert import IRCAlert


logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events in the system."""
    LOG_ENTRY = "log_entry"
    THREAT_DETECTED = "threat_detected"
    NEW_HOST = "new_host"
    PATTERN_DETECTED = "pattern_detected"
    IRC_CONNECTED = "irc_connected"
    IRC_DISCONNECTED = "irc_disconnected"
    IRC_ERROR = "irc_error"
    MONITORING_STARTED = "monitoring_started"
    MONITORING_STOPPED = "monitoring_stopped"
    MONITORING_ERROR = "monitoring_error"
    ALERT_SENT = "alert_sent"
    SYSTEM_ERROR = "system_error"


@dataclass
class Event:
    """Represents a system event."""
    event_type: EventType
    timestamp: datetime
    data: Dict[str, Any]
    source: str = "unknown"


class EventManager:
    """
    Central event manager for coordinating system components.
    
    Provides event publishing, subscription, and processing with
    thread-safe operations and error handling.
    """
    
    def __init__(self, max_queue_size: int = 1000, worker_threads: int = 2):
        """
        Initialize the event manager.
        
        Args:
            max_queue_size: Maximum size of event queue
            worker_threads: Number of worker threads for event processing
        """
        self.max_queue_size = max_queue_size
        self.worker_threads = worker_threads
        
        # Event processing
        self.event_queue: Queue[Event] = Queue(maxsize=max_queue_size)
        self.subscribers: Dict[EventType, List[Callable[[Event], None]]] = {}
        self.workers: List[threading.Thread] = []
        self.shutdown_event = threading.Event()
        
        # Event statistics
        self.events_processed = 0
        self.events_dropped = 0
        self.processing_errors = 0
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Start worker threads
        self._start_workers()
    
    def subscribe(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Type of event to subscribe to
            callback: Function to call when event occurs
        """
        with self._lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            
            if callback not in self.subscribers[event_type]:
                self.subscribers[event_type].append(callback)
                logger.debug(f"Subscribed to {event_type.value} events")
    
    def unsubscribe(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """
        Unsubscribe from events of a specific type.
        
        Args:
            event_type: Type of event to unsubscribe from
            callback: Function to remove from subscribers
        """
        with self._lock:
            if event_type in self.subscribers and callback in self.subscribers[event_type]:
                self.subscribers[event_type].remove(callback)
                logger.debug(f"Unsubscribed from {event_type.value} events")
    
    def publish(self, event_type: EventType, data: Dict[str, Any], source: str = "unknown") -> bool:
        """
        Publish an event to the system.
        
        Args:
            event_type: Type of event
            data: Event data
            source: Source component that generated the event
            
        Returns:
            True if event was queued successfully, False otherwise
        """
        event = Event(
            event_type=event_type,
            timestamp=datetime.now(),
            data=data,
            source=source
        )
        
        try:
            self.event_queue.put_nowait(event)
            return True
        except Exception as e:
            self.events_dropped += 1
            logger.warning(f"Failed to queue event {event_type.value}: {e}")
            return False
    
    def publish_log_entry(self, log_entry: LogEntry, source: str = "log_monitor") -> bool:
        """
        Publish a log entry event.
        
        Args:
            log_entry: LogEntry object
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.LOG_ENTRY,
            {"log_entry": log_entry},
            source
        )
    
    def publish_threat_detected(self, threat: ThreatAssessment, source_ip: str, 
                              log_entry: LogEntry, source: str = "threat_analyzer") -> bool:
        """
        Publish a threat detection event.
        
        Args:
            threat: ThreatAssessment object
            source_ip: IP address of threat source
            log_entry: Original log entry
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.THREAT_DETECTED,
            {
                "threat": threat,
                "source_ip": source_ip,
                "log_entry": log_entry
            },
            source
        )
    
    def publish_new_host(self, source_ip: str, first_seen: datetime, 
                        source: str = "alert_manager") -> bool:
        """
        Publish a new host detection event.
        
        Args:
            source_ip: IP address of new host
            first_seen: When the host was first seen
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.NEW_HOST,
            {
                "source_ip": source_ip,
                "first_seen": first_seen
            },
            source
        )
    
    def publish_pattern_detected(self, pattern: Dict[str, Any], 
                               source: str = "threat_analyzer") -> bool:
        """
        Publish a pattern detection event.
        
        Args:
            pattern: Pattern detection result
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.PATTERN_DETECTED,
            {"pattern": pattern},
            source
        )
    
    def publish_irc_status(self, status: str, message: str = "", 
                          source: str = "irc_notifier") -> bool:
        """
        Publish IRC status change event.
        
        Args:
            status: Status (connected, disconnected, error)
            message: Additional status message
            source: Source component
            
        Returns:
            True if published successfully
        """
        event_type_map = {
            "connected": EventType.IRC_CONNECTED,
            "disconnected": EventType.IRC_DISCONNECTED,
            "error": EventType.IRC_ERROR
        }
        
        event_type = event_type_map.get(status, EventType.IRC_ERROR)
        return self.publish(
            event_type,
            {"status": status, "message": message},
            source
        )
    
    def publish_monitoring_status(self, status: str, message: str = "", 
                                source: str = "log_monitor") -> bool:
        """
        Publish monitoring status change event.
        
        Args:
            status: Status (started, stopped, error)
            message: Additional status message
            source: Source component
            
        Returns:
            True if published successfully
        """
        event_type_map = {
            "started": EventType.MONITORING_STARTED,
            "stopped": EventType.MONITORING_STOPPED,
            "error": EventType.MONITORING_ERROR
        }
        
        event_type = event_type_map.get(status, EventType.MONITORING_ERROR)
        return self.publish(
            event_type,
            {"status": status, "message": message},
            source
        )
    
    def publish_alert_sent(self, alert: IRCAlert, success: bool, 
                          source: str = "alert_manager") -> bool:
        """
        Publish alert sent event.
        
        Args:
            alert: IRCAlert that was sent
            success: Whether sending was successful
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.ALERT_SENT,
            {
                "alert": alert,
                "success": success
            },
            source
        )
    
    def publish_system_error(self, error_message: str, exception: Optional[Exception] = None,
                           source: str = "system") -> bool:
        """
        Publish system error event.
        
        Args:
            error_message: Error description
            exception: Optional exception object
            source: Source component
            
        Returns:
            True if published successfully
        """
        return self.publish(
            EventType.SYSTEM_ERROR,
            {
                "error_message": error_message,
                "exception": str(exception) if exception else None
            },
            source
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get event processing statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "events_processed": self.events_processed,
            "events_dropped": self.events_dropped,
            "processing_errors": self.processing_errors,
            "queue_size": self.event_queue.qsize(),
            "max_queue_size": self.max_queue_size,
            "worker_threads": len(self.workers),
            "active_subscriptions": {
                event_type.value: len(callbacks)
                for event_type, callbacks in self.subscribers.items()
            }
        }
    
    def shutdown(self) -> None:
        """Shutdown the event manager and stop all workers."""
        logger.info("Shutting down event manager")
        self.shutdown_event.set()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        # Clear remaining events
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except Empty:
                break
    
    def _start_workers(self) -> None:
        """Start worker threads for event processing."""
        for i in range(self.worker_threads):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"EventWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        logger.info(f"Started {self.worker_threads} event worker threads")
    
    def _worker_loop(self) -> None:
        """Worker thread loop for processing events."""
        while not self.shutdown_event.is_set():
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1.0)
                self._process_event(event)
                self.events_processed += 1
                
            except Empty:
                continue
            except Exception as e:
                self.processing_errors += 1
                logger.error(f"Error in event worker: {e}")
    
    def _process_event(self, event: Event) -> None:
        """
        Process a single event by notifying all subscribers.
        
        Args:
            event: Event to process
        """
        with self._lock:
            subscribers = self.subscribers.get(event.event_type, []).copy()
        
        # Notify all subscribers
        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback for {event.event_type.value}: {e}")