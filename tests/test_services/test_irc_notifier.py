"""
Unit tests for IRC notifier service.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import time
from queue import Queue

from src.honeypot_monitor.services.irc_notifier import IRCNotifier
from src.honeypot_monitor.models.irc_alert import IRCAlert


class TestIRCNotifier:
    """Test cases for IRCNotifier class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.server = "irc.example.com"
        self.port = 6667
        self.nickname = "test-bot"
        self.channel = "#test-channel"
        
        self.notifier = IRCNotifier(
            server=self.server,
            port=self.port,
            nickname=self.nickname,
            channel=self.channel,
            reconnect_delay=1,  # Short delay for testing
            max_reconnect_attempts=3,
            rate_limit_messages=3,
            rate_limit_window=10
        )
    
    def teardown_method(self):
        """Clean up after tests."""
        if self.notifier:
            self.notifier.disconnect()
    
    def test_initialization(self):
        """Test IRCNotifier initialization."""
        assert self.notifier.server == self.server
        assert self.notifier.port == self.port
        assert self.notifier.nickname == self.nickname
        assert self.notifier.channel == self.channel
        assert not self.notifier.connected
        assert not self.notifier.joined_channel
        assert self.notifier.reconnect_attempts == 0
    
    def test_initialization_with_ssl(self):
        """Test IRCNotifier initialization with SSL."""
        ssl_notifier = IRCNotifier(
            server=self.server,
            port=6697,
            nickname=self.nickname,
            channel=self.channel,
            use_ssl=True
        )
        
        assert ssl_notifier.use_ssl is True
        assert ssl_notifier.port == 6697
    
    @patch('threading.Thread')
    def test_connect_success(self, mock_thread):
        """Test successful IRC connection."""
        # Setup mocks
        mock_reactor = Mock()
        mock_server = Mock()
        mock_connection = Mock()
        mock_factory = Mock()
        mock_thread_instance = Mock()
        
        mock_thread.return_value = mock_thread_instance
        
        with patch('src.honeypot_monitor.services.irc_notifier.irc.client.Reactor') as mock_reactor_class:
            with patch('src.honeypot_monitor.services.irc_notifier.irc.connection.Factory') as mock_factory_class:
                mock_reactor_class.return_value = mock_reactor
                mock_reactor.server.return_value = mock_server
                mock_server.connect.return_value = mock_connection
                mock_factory_class.return_value = mock_factory
                
                # Test connection
                result = self.notifier.connect()
                
                assert result is True
                mock_reactor_class.assert_called_once()
                mock_factory_class.assert_called_once()
                mock_server.connect.assert_called_once_with(
                    self.server, self.port, self.nickname, connect_factory=mock_factory
                )
    
    @patch('threading.Thread')
    def test_connect_with_ssl(self, mock_thread):
        """Test IRC connection with SSL."""
        ssl_notifier = IRCNotifier(
            server=self.server,
            port=6697,
            nickname=self.nickname,
            channel=self.channel,
            use_ssl=True
        )
        
        # Setup mocks
        mock_reactor = Mock()
        mock_server = Mock()
        mock_connection = Mock()
        mock_factory = Mock()
        mock_thread_instance = Mock()
        
        mock_thread.return_value = mock_thread_instance
        
        with patch('src.honeypot_monitor.services.irc_notifier.irc.client.Reactor') as mock_reactor_class:
            with patch('src.honeypot_monitor.services.irc_notifier.irc.connection.Factory') as mock_factory_class:
                with patch('ssl.create_default_context') as mock_ssl_context:
                    mock_reactor_class.return_value = mock_reactor
                    mock_reactor.server.return_value = mock_server
                    mock_server.connect.return_value = mock_connection
                    mock_factory_class.return_value = mock_factory
                    
                    mock_context = Mock()
                    mock_ssl_context.return_value = mock_context
                    
                    result = ssl_notifier.connect()
                    
                    assert result is True
                    mock_ssl_context.assert_called_once()
                    # Check that SSL factory was created with wrapper
                    assert mock_factory_class.call_count == 2  # Once for regular, once for SSL
                    mock_server.connect.assert_called_once_with(
                        self.server, 6697, self.nickname, connect_factory=mock_factory
                    )
    
    @patch('src.honeypot_monitor.services.irc_notifier.irc.client.Reactor')
    def test_connect_failure(self, mock_reactor_class):
        """Test IRC connection failure."""
        # Setup mocks to raise exception
        mock_reactor = Mock()
        mock_server = Mock()
        
        mock_reactor_class.return_value = mock_reactor
        mock_reactor.server.return_value = mock_server
        mock_server.connect.side_effect = Exception("Connection failed")
        
        # Test connection failure
        result = self.notifier.connect()
        
        assert result is False
    
    def test_disconnect(self):
        """Test IRC disconnection."""
        # Setup mock connection
        mock_connection = Mock()
        mock_connection.is_connected.return_value = True
        self.notifier.connection = mock_connection
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        # Test disconnection
        self.notifier.disconnect()
        
        mock_connection.quit.assert_called_once()
        assert not self.notifier.connected
        assert not self.notifier.joined_channel
        assert self.notifier.shutdown_event.is_set()
    
    def test_is_connected(self):
        """Test connection status check."""
        # Initially not connected
        assert not self.notifier.is_connected()
        
        # Set connected but not joined
        self.notifier.connected = True
        assert not self.notifier.is_connected()
        
        # Set both connected and joined
        self.notifier.joined_channel = True
        assert self.notifier.is_connected()
    
    def test_get_connection_status(self):
        """Test getting connection status."""
        status = self.notifier.get_connection_status()
        
        expected_keys = {
            'connected', 'joined_channel', 'server', 'port', 'channel',
            'nickname', 'use_ssl', 'reconnect_attempts', 'queue_size'
        }
        
        assert set(status.keys()) == expected_keys
        assert status['server'] == self.server
        assert status['port'] == self.port
        assert status['channel'] == self.channel
        assert status['nickname'] == self.nickname
    
    def test_rate_limiting(self):
        """Test message rate limiting."""
        # Send messages up to the limit
        for i in range(3):  # rate_limit_messages = 3
            assert self.notifier._check_rate_limit()
        
        # Next message should be rate limited
        assert not self.notifier._check_rate_limit()
        
        # Wait for rate limit window to pass
        time.sleep(0.1)  # Small delay for test
        
        # Manually clear timestamps to simulate window passing
        self.notifier.message_timestamps.clear()
        
        # Should be able to send again
        assert self.notifier._check_rate_limit()
    
    def test_send_message_success(self):
        """Test successful message sending."""
        # Setup connected state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        message = "Test message"
        result = self.notifier.send_message(message)
        
        assert result is True
        assert not self.notifier.message_queue.empty()
    
    def test_send_message_empty(self):
        """Test sending empty message."""
        result = self.notifier.send_message("")
        assert result is False
        
        result = self.notifier.send_message("   ")
        assert result is False
    
    def test_send_message_rate_limited(self):
        """Test message sending when rate limited."""
        # Fill up rate limit
        for i in range(3):
            self.notifier._check_rate_limit()
        
        # Next message should fail due to rate limiting
        result = self.notifier.send_message("Test message")
        assert result is False
    
    def test_send_alert(self):
        """Test sending IRC alert."""
        # Create test alert
        alert = IRCAlert(
            alert_type='new_host',
            timestamp=datetime.now(),
            source_ip='192.168.1.100',
            message='Test alert',
            severity='medium'
        )
        
        # Setup connected state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        result = self.notifier.send_alert(alert)
        
        assert result is True
        assert alert.sent is True
    
    def test_send_alert_invalid_type(self):
        """Test sending invalid alert type."""
        result = self.notifier.send_alert("not an alert")
        assert result is False
    
    def test_send_new_host_alert(self):
        """Test sending new host alert."""
        ip = "192.168.1.100"
        first_seen = datetime.now()
        
        # Setup connected state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        result = self.notifier.send_new_host_alert(ip, first_seen)
        assert result is True
    
    def test_send_threat_alert(self):
        """Test sending threat alert."""
        ip = "192.168.1.100"
        description = "Suspicious activity detected"
        
        # Setup connected state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        result = self.notifier.send_threat_alert(ip, description, 'high')
        assert result is True
    
    def test_send_interesting_traffic_alert(self):
        """Test sending interesting traffic alert."""
        ip = "192.168.1.100"
        description = "Unusual command sequence"
        
        # Setup connected state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        result = self.notifier.send_interesting_traffic_alert(ip, description)
        assert result is True
    
    def test_set_callbacks(self):
        """Test setting callback functions."""
        on_connect = Mock()
        on_disconnect = Mock()
        on_error = Mock()
        
        self.notifier.set_callbacks(
            on_connect=on_connect,
            on_disconnect=on_disconnect,
            on_error=on_error
        )
        
        assert self.notifier.on_connect_callback == on_connect
        assert self.notifier.on_disconnect_callback == on_disconnect
        assert self.notifier.on_error_callback == on_error
    
    def test_on_welcome_event(self):
        """Test handling welcome event."""
        mock_connection = Mock()
        mock_event = Mock()
        
        self.notifier._on_welcome(mock_connection, mock_event)
        
        assert self.notifier.connected is True
        mock_connection.join.assert_called_once_with(self.channel)
    
    def test_on_join_event(self):
        """Test handling join event."""
        mock_connection = Mock()
        mock_event = Mock()
        mock_event.target = self.channel
        
        # Setup callback
        on_connect_callback = Mock()
        self.notifier.on_connect_callback = on_connect_callback
        
        self.notifier._on_join(mock_connection, mock_event)
        
        assert self.notifier.joined_channel is True
        assert self.notifier.reconnect_attempts == 0
        on_connect_callback.assert_called_once()
    
    def test_on_join_event_wrong_channel(self):
        """Test handling join event for wrong channel."""
        mock_connection = Mock()
        mock_event = Mock()
        mock_event.target = "#other-channel"
        
        self.notifier._on_join(mock_connection, mock_event)
        
        assert self.notifier.joined_channel is False
    
    def test_on_disconnect_event(self):
        """Test handling disconnect event."""
        mock_connection = Mock()
        mock_event = Mock()
        
        # Setup callback
        on_disconnect_callback = Mock()
        self.notifier.on_disconnect_callback = on_disconnect_callback
        
        # Setup initial state
        self.notifier.connected = True
        self.notifier.joined_channel = True
        
        with patch.object(self.notifier, '_attempt_reconnect') as mock_reconnect:
            self.notifier._on_disconnect(mock_connection, mock_event)
            
            assert self.notifier.connected is False
            assert self.notifier.joined_channel is False
            on_disconnect_callback.assert_called_once()
            mock_reconnect.assert_called_once()
    
    def test_on_error_event(self):
        """Test handling error event."""
        mock_connection = Mock()
        mock_event = Mock()
        mock_event.arguments = ["Test error message"]
        
        # Setup callback
        on_error_callback = Mock()
        self.notifier.on_error_callback = on_error_callback
        
        self.notifier._on_error(mock_connection, mock_event)
        
        on_error_callback.assert_called_once_with("IRC error: Test error message")
    
    def test_on_nickname_in_use_event(self):
        """Test handling nickname in use event."""
        mock_connection = Mock()
        mock_event = Mock()
        
        original_nickname = self.notifier.nickname
        
        self.notifier._on_nickname_in_use(mock_connection, mock_event)
        
        # Should have changed nickname
        assert self.notifier.nickname != original_nickname
        assert self.notifier.nickname.startswith(original_nickname + "_")
        mock_connection.nick.assert_called_once_with(self.notifier.nickname)
    
    def test_attempt_reconnect_max_attempts(self):
        """Test reconnection with maximum attempts reached."""
        self.notifier.reconnect_attempts = self.notifier.max_reconnect_attempts
        
        with patch.object(self.notifier, 'connect') as mock_connect:
            self.notifier._attempt_reconnect()
            
            # Should not attempt to reconnect
            mock_connect.assert_not_called()
    
    def test_attempt_reconnect_success(self):
        """Test successful reconnection attempt."""
        self.notifier.reconnect_attempts = 1
        
        with patch.object(self.notifier, 'connect') as mock_connect:
            with patch('time.sleep'):  # Skip sleep for testing
                self.notifier._attempt_reconnect()
                
                assert self.notifier.reconnect_attempts == 2
                mock_connect.assert_called_once()


class TestIRCNotifierIntegration:
    """Integration tests for IRCNotifier."""
    
    def test_message_queue_processing(self):
        """Test message queue processing in worker thread."""
        notifier = IRCNotifier(
            server="irc.example.com",
            nickname="test-bot",
            channel="#test"
        )
        
        # Setup mock connection
        mock_connection = Mock()
        notifier.connection = mock_connection
        notifier.connected = True
        notifier.joined_channel = True
        
        # Start worker thread
        notifier.worker_thread = threading.Thread(target=notifier._worker_loop, daemon=True)
        notifier.worker_thread.start()
        
        # Send a message
        test_message = "Test message"
        notifier.message_queue.put(test_message)
        
        # Wait a bit for processing
        time.sleep(0.1)
        
        # Stop worker
        notifier.shutdown_event.set()
        notifier.worker_thread.join(timeout=1)
        
        # Verify message was sent
        mock_connection.privmsg.assert_called_with("#test", test_message)
    
    def test_full_alert_workflow(self):
        """Test complete alert sending workflow."""
        notifier = IRCNotifier(
            server="irc.example.com",
            nickname="test-bot",
            channel="#test"
        )
        
        # Setup connected state
        notifier.connected = True
        notifier.joined_channel = True
        
        # Create and send alert
        alert = IRCAlert.create_new_host_alert("192.168.1.100", datetime.now())
        
        result = notifier.send_alert(alert)
        
        assert result is True
        assert alert.sent is True
        assert not notifier.message_queue.empty()
        
        # Clean up
        notifier.disconnect()


if __name__ == '__main__':
    pytest.main([__file__])