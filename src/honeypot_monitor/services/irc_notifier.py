"""
IRC notification service for honeypot monitoring.
"""

import ssl
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from queue import Queue, Empty
import logging
import socket

import irc.client
import irc.connection

from ..models.irc_alert import IRCAlert


logger = logging.getLogger(__name__)


class IRCNotifier:
    """
    IRC notification service for sending honeypot alerts to IRC channels.
    
    Provides connection management, automatic reconnection, SSL support,
    and rate limiting to prevent channel flooding.
    """
    
    def __init__(self, 
                 server: str,
                 port: int = 6667,
                 nickname: str = "honeypot-monitor",
                 channel: str = "#security-alerts",
                 use_ssl: bool = False,
                 reconnect_delay: int = 30,
                 max_reconnect_attempts: int = 10,
                 rate_limit_messages: int = 5,
                 rate_limit_window: int = 60):
        """
        Initialize IRC notifier.
        
        Args:
            server: IRC server hostname
            port: IRC server port
            nickname: Bot nickname
            channel: IRC channel to join
            use_ssl: Whether to use SSL connection
            reconnect_delay: Delay between reconnection attempts (seconds)
            max_reconnect_attempts: Maximum reconnection attempts
            rate_limit_messages: Maximum messages per rate limit window
            rate_limit_window: Rate limit window in seconds
        """
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channel = channel
        self.use_ssl = use_ssl
        self.reconnect_delay = reconnect_delay
        self.max_reconnect_attempts = max_reconnect_attempts
        
        # Rate limiting
        self.rate_limit_messages = rate_limit_messages
        self.rate_limit_window = rate_limit_window
        self.message_timestamps: List[datetime] = []
        
        # Connection state
        self.reactor: Optional[irc.client.Reactor] = None
        self.connection: Optional[irc.connection.ServerConnection] = None
        self.connected = False
        self.joined_channel = False
        self.reconnect_attempts = 0
        
        # Threading
        self.message_queue: Queue[str] = Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        
        # Callbacks
        self.on_connect_callback: Optional[Callable[[], None]] = None
        self.on_disconnect_callback: Optional[Callable[[], None]] = None
        self.on_error_callback: Optional[Callable[[str], None]] = None
        
        # Event handlers will be setup when connecting
    
    def _setup_event_handlers(self) -> None:
        """Setup IRC event handlers."""
        if self.reactor:
            self.reactor.add_global_handler("welcome", self._on_welcome)
            self.reactor.add_global_handler("join", self._on_join)
            self.reactor.add_global_handler("disconnect", self._on_disconnect)
            self.reactor.add_global_handler("error", self._on_error)
            self.reactor.add_global_handler("nicknameinuse", self._on_nickname_in_use)
    
    def connect(self) -> bool:
        """
        Connect to IRC server.
        
        Returns:
            True if connection initiated successfully, False otherwise
        """
        try:
            logger.info(f"Connecting to IRC server {self.server}:{self.port}")
            
            # Create reactor if not exists
            if self.reactor is None:
                self.reactor = irc.client.Reactor()
                self._setup_event_handlers()
            
            # Create connection factory for SSL if needed
            connect_factory = irc.connection.Factory()
            if self.use_ssl:
                # Use modern SSL context approach
                ssl_context = ssl.create_default_context()
                connect_factory = irc.connection.Factory(wrapper=ssl_context.wrap_socket)
            
            # Connect to server
            self.connection = self.reactor.server().connect(
                self.server,
                self.port,
                self.nickname,
                connect_factory=connect_factory
            )
            
            # Start worker thread for message processing
            if not self.worker_thread or not self.worker_thread.is_alive():
                self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
                self.worker_thread.start()
            
            # Start reactor in separate thread
            reactor_thread = threading.Thread(target=self._reactor_loop, daemon=True)
            reactor_thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to IRC server: {e}")
            if self.on_error_callback:
                self.on_error_callback(f"Connection failed: {e}")
            return False
    
    def disconnect(self) -> None:
        """Disconnect from IRC server."""
        logger.info("Disconnecting from IRC server")
        
        # Signal shutdown
        self.shutdown_event.set()
        
        # Disconnect from server
        if self.connection and self.connection.is_connected():
            self.connection.quit("Honeypot monitor shutting down")
        
        # Reset state
        self.connected = False
        self.joined_channel = False
        self.reconnect_attempts = 0
        
        # Clear message queue
        while not self.message_queue.empty():
            try:
                self.message_queue.get_nowait()
            except Empty:
                break
    
    def is_connected(self) -> bool:
        """
        Check if connected to IRC server and joined channel.
        
        Returns:
            True if connected and joined channel, False otherwise
        """
        return self.connected and self.joined_channel
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get detailed connection status.
        
        Returns:
            Dictionary with connection status information
        """
        return {
            'connected': self.connected,
            'joined_channel': self.joined_channel,
            'server': self.server,
            'port': self.port,
            'channel': self.channel,
            'nickname': self.nickname,
            'use_ssl': self.use_ssl,
            'reconnect_attempts': self.reconnect_attempts,
            'queue_size': self.message_queue.qsize()
        }
    
    def send_message(self, message: str) -> bool:
        """
        Send a message to the IRC channel.
        
        Args:
            message: Message to send
            
        Returns:
            True if message queued successfully, False otherwise
        """
        if not message or not message.strip():
            return False
        
        # Check rate limiting
        if not self._check_rate_limit():
            logger.warning("Rate limit exceeded, dropping message")
            return False
        
        # Queue message for sending
        try:
            self.message_queue.put(message.strip(), timeout=1)
            return True
        except Exception as e:
            logger.error(f"Failed to queue message: {e}")
            return False
    
    def send_alert(self, alert: IRCAlert) -> bool:
        """
        Send an IRC alert.
        
        Args:
            alert: IRCAlert to send
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        if not isinstance(alert, IRCAlert):
            logger.error("Invalid alert type")
            return False
        
        formatted_message = alert.format_for_irc()
        success = self.send_message(formatted_message)
        
        if success:
            alert.mark_as_sent()
            logger.info(f"Sent IRC alert: {alert.alert_type} for {alert.source_ip}")
        else:
            logger.warning(f"Failed to send IRC alert: {alert.alert_type} for {alert.source_ip}")
        
        return success
    
    def send_new_host_alert(self, ip: str, first_seen: datetime) -> bool:
        """
        Send a new host alert.
        
        Args:
            ip: IP address of new host
            first_seen: When the host was first seen
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        alert = IRCAlert.create_new_host_alert(ip, first_seen)
        return self.send_alert(alert)
    
    def send_threat_alert(self, ip: str, threat_description: str, severity: str = 'high') -> bool:
        """
        Send a threat alert.
        
        Args:
            ip: IP address of threat source
            threat_description: Description of the threat
            severity: Threat severity level
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        alert = IRCAlert.create_threat_alert(ip, threat_description, severity)
        return self.send_alert(alert)
    
    def send_interesting_traffic_alert(self, ip: str, activity_description: str) -> bool:
        """
        Send an interesting traffic alert.
        
        Args:
            ip: IP address of traffic source
            activity_description: Description of interesting activity
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        alert = IRCAlert.create_interesting_traffic_alert(ip, activity_description)
        return self.send_alert(alert)
    
    def set_callbacks(self,
                     on_connect: Optional[Callable[[], None]] = None,
                     on_disconnect: Optional[Callable[[], None]] = None,
                     on_error: Optional[Callable[[str], None]] = None) -> None:
        """
        Set callback functions for IRC events.
        
        Args:
            on_connect: Called when successfully connected and joined channel
            on_disconnect: Called when disconnected from server
            on_error: Called when an error occurs
        """
        self.on_connect_callback = on_connect
        self.on_disconnect_callback = on_disconnect
        self.on_error_callback = on_error
    
    def _check_rate_limit(self) -> bool:
        """
        Check if message sending is within rate limits.
        
        Returns:
            True if within rate limits, False otherwise
        """
        now = datetime.now()
        
        # Remove old timestamps outside the window
        cutoff = now - timedelta(seconds=self.rate_limit_window)
        self.message_timestamps = [ts for ts in self.message_timestamps if ts > cutoff]
        
        # Check if we're within limits
        if len(self.message_timestamps) >= self.rate_limit_messages:
            return False
        
        # Add current timestamp
        self.message_timestamps.append(now)
        return True
    
    def _worker_loop(self) -> None:
        """Worker thread loop for processing message queue."""
        while not self.shutdown_event.is_set():
            try:
                # Get message from queue with timeout
                message = self.message_queue.get(timeout=1)
                
                # Send message if connected
                if self.is_connected():
                    self.connection.privmsg(self.channel, message)
                    logger.debug(f"Sent IRC message: {message}")
                else:
                    logger.warning(f"Not connected, dropping message: {message}")
                
                self.message_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
    
    def _reactor_loop(self) -> None:
        """Reactor loop for handling IRC events."""
        try:
            while not self.shutdown_event.is_set() and self.reactor:
                self.reactor.process_once(timeout=0.1)
        except Exception as e:
            logger.error(f"Reactor loop error: {e}")
    
    def _on_welcome(self, connection, event) -> None:
        """Handle welcome event (successful connection)."""
        logger.info("Connected to IRC server, joining channel")
        self.connected = True
        connection.join(self.channel)
    
    def _on_join(self, connection, event) -> None:
        """Handle join event (successfully joined channel)."""
        if event.target == self.channel:
            logger.info(f"Joined IRC channel {self.channel}")
            self.joined_channel = True
            self.reconnect_attempts = 0
            
            if self.on_connect_callback:
                self.on_connect_callback()
    
    def _on_disconnect(self, connection, event) -> None:
        """Handle disconnect event."""
        logger.warning("Disconnected from IRC server")
        self.connected = False
        self.joined_channel = False
        
        if self.on_disconnect_callback:
            self.on_disconnect_callback()
        
        # Attempt reconnection if not shutting down
        if not self.shutdown_event.is_set():
            self._attempt_reconnect()
    
    def _on_error(self, connection, event) -> None:
        """Handle error event."""
        error_msg = f"IRC error: {event.arguments[0] if event.arguments else 'Unknown error'}"
        logger.error(error_msg)
        
        if self.on_error_callback:
            self.on_error_callback(error_msg)
    
    def _on_nickname_in_use(self, connection, event) -> None:
        """Handle nickname in use event."""
        new_nickname = f"{self.nickname}_{int(time.time()) % 1000}"
        logger.warning(f"Nickname {self.nickname} in use, trying {new_nickname}")
        connection.nick(new_nickname)
        self.nickname = new_nickname
    
    def _attempt_reconnect(self) -> None:
        """Attempt to reconnect to IRC server."""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            logger.error("Maximum reconnection attempts reached")
            return
        
        self.reconnect_attempts += 1
        logger.info(f"Attempting reconnection {self.reconnect_attempts}/{self.max_reconnect_attempts}")
        
        # Wait before reconnecting
        time.sleep(self.reconnect_delay)
        
        # Try to reconnect
        if not self.shutdown_event.is_set():
            self.connect()