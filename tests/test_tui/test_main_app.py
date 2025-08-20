"""
Tests for the main TUI application.
"""

import pytest
from unittest.mock import Mock, patch
from textual.app import App
from textual.widgets import Header, Footer, Static

from honeypot_monitor.tui.main_app import HoneypotMonitorApp
from honeypot_monitor.config.settings import Settings


class TestHoneypotMonitorApp:
    """Test cases for the main TUI application."""
    
    def test_app_initialization(self):
        """Test that the app initializes correctly."""
        app = HoneypotMonitorApp()
        
        assert app.TITLE == "Honeypot Monitor CLI"
        assert app.SUB_TITLE == "Real-time honeypot activity monitoring"
        assert app.current_view == "dashboard"
        assert app.monitoring_status == "Disconnected"
        assert app.irc_status == "Disconnected"
    
    def test_app_initialization_with_config(self):
        """Test that the app initializes correctly with config."""
        mock_config = Mock(spec=Settings)
        app = HoneypotMonitorApp(config=mock_config)
        
        assert app.config == mock_config
        assert app.current_view == "dashboard"
    
    def test_key_bindings_defined(self):
        """Test that all required key bindings are defined."""
        app = HoneypotMonitorApp()
        
        # Extract binding keys
        binding_keys = [binding.key for binding in app.BINDINGS]
        
        expected_keys = ["q", "d", "l", "a", "s", "h", "r"]
        for key in expected_keys:
            assert key in binding_keys
    
    @pytest.mark.asyncio
    async def test_app_compose_structure(self):
        """Test that the app creates the correct widget structure."""
        app = HoneypotMonitorApp()
        
        # Use textual's testing utilities
        async with app.run_test() as pilot:
            # Check that main components exist
            assert app.query_one("Header")
            assert app.query_one("Footer")
            assert app.query_one("#main-container")
            assert app.query_one("#content-area")
            assert app.query_one("#main-content")
            assert app.query_one("#status-bar")
    
    @pytest.mark.asyncio
    async def test_status_bar_elements(self):
        """Test that status bar contains all required elements."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Check status bar elements
            assert app.query_one("#monitoring-label")
            assert app.query_one("#monitoring-status")
            assert app.query_one("#irc-label")
            assert app.query_one("#irc-status")
            assert app.query_one("#view-label")
            assert app.query_one("#current-view")
    
    @pytest.mark.asyncio
    async def test_navigation_actions(self):
        """Test navigation between different views."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Test dashboard action
            await pilot.press("d")
            assert app.current_view == "dashboard"
            
            # Test logs action
            await pilot.press("l")
            assert app.current_view == "logs"
            
            # Test analysis action
            await pilot.press("a")
            assert app.current_view == "analysis"
            
            # Test settings action
            await pilot.press("s")
            assert app.current_view == "settings"
    
    @pytest.mark.asyncio
    async def test_help_action(self):
        """Test that help action displays help content."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            await pilot.press("h")
            
            # Check that help content is displayed
            content = app.query_one("#content-text")
            assert "Honeypot Monitor CLI - Help" in content.renderable
    
    @pytest.mark.asyncio
    async def test_refresh_action(self):
        """Test refresh action for different views."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Test refresh on dashboard
            app.current_view = "dashboard"
            await pilot.press("r")
            assert app.current_view == "dashboard"
            
            # Test refresh on logs
            app.current_view = "logs"
            await pilot.press("r")
            assert app.current_view == "logs"
    
    @pytest.mark.asyncio
    async def test_quit_action(self):
        """Test that quit action works."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Mock the exit method to prevent actual exit
            with patch.object(app, 'exit') as mock_exit:
                await pilot.press("q")
                mock_exit.assert_called_once()
    
    def test_update_monitoring_status(self):
        """Test updating monitoring status."""
        app = HoneypotMonitorApp()
        
        # Test status update before mounting
        app.update_monitoring_status("Connected")
        assert app.monitoring_status == "Connected"
    
    @pytest.mark.asyncio
    async def test_update_monitoring_status_after_mount(self):
        """Test updating monitoring status after app is mounted."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            app.update_monitoring_status("Connected")
            
            status_widget = app.query_one("#monitoring-status")
            assert "Connected" in str(status_widget.renderable)
    
    def test_update_irc_status(self):
        """Test updating IRC status."""
        app = HoneypotMonitorApp()
        
        # Test status update before mounting
        app.update_irc_status("Connected")
        assert app.irc_status == "Connected"
    
    @pytest.mark.asyncio
    async def test_update_irc_status_after_mount(self):
        """Test updating IRC status after app is mounted."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            app.update_irc_status("Connected")
            
            status_widget = app.query_one("#irc-status")
            assert "Connected" in str(status_widget.renderable)
    
    @pytest.mark.asyncio
    async def test_view_status_update(self):
        """Test that view status updates correctly."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Change to logs view
            await pilot.press("l")
            
            view_widget = app.query_one("#current-view")
            assert "Logs" in str(view_widget.renderable)
    
    @pytest.mark.asyncio
    async def test_main_content_update(self):
        """Test that main content updates correctly."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Test content update
            test_content = "Test Content"
            app._update_main_content(test_content)
            
            content_widget = app.query_one("#content-text")
            assert test_content in str(content_widget.renderable)
    
    def test_main_function_import(self):
        """Test that main function can be imported and called."""
        from honeypot_monitor.tui.main_app import main
        
        # Mock the app to prevent actual execution
        with patch('honeypot_monitor.tui.main_app.HoneypotMonitorApp') as mock_app_class:
            mock_app = Mock()
            mock_app_class.return_value = mock_app
            
            main()
            
            mock_app_class.assert_called_once()
            mock_app.run.assert_called_once()


class TestAppIntegration:
    """Integration tests for the TUI application."""
    
    @pytest.mark.asyncio
    async def test_full_navigation_cycle(self):
        """Test navigating through all views in sequence."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Start at dashboard
            assert app.current_view == "dashboard"
            
            # Navigate through all views
            await pilot.press("l")  # logs
            assert app.current_view == "logs"
            
            await pilot.press("a")  # analysis
            assert app.current_view == "analysis"
            
            await pilot.press("s")  # settings
            assert app.current_view == "settings"
            
            await pilot.press("d")  # back to dashboard
            assert app.current_view == "dashboard"
    
    @pytest.mark.asyncio
    async def test_status_updates_during_navigation(self):
        """Test that status updates work during navigation."""
        app = HoneypotMonitorApp()
        
        async with app.run_test() as pilot:
            # Update statuses
            app.update_monitoring_status("Active")
            app.update_irc_status("Connected")
            
            # Navigate and check statuses persist
            await pilot.press("l")
            
            monitoring_widget = app.query_one("#monitoring-status")
            irc_widget = app.query_one("#irc-status")
            
            assert "Active" in str(monitoring_widget.renderable)
            assert "Connected" in str(irc_widget.renderable)