"""
Main TUI application class for the Honeypot Monitor CLI.

This module provides the primary application interface using the textual framework,
implementing a terminal-based user interface similar to lazydocker for monitoring
honeypot activity.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static
from textual.binding import Binding
from textual.reactive import reactive
from typing import Optional
import logging

from .dashboard import Dashboard
from .log_viewer import LogViewer
from .analysis_panel import AnalysisPanel
from .settings_panel import SettingsPanel
from ..services.service_coordinator import ServiceCoordinator
from ..services.event_manager import EventType, Event
from ..models.log_entry import LogEntry
from ..models.threat_assessment import ThreatAssessment
from ..models.irc_alert import IRCAlert


class HoneypotMonitorApp(App):
    """Main TUI application for honeypot monitoring."""
    
    CSS_PATH = ["main_app.tcss", "dashboard.tcss", "analysis_panel.tcss", "settings_panel.tcss"]
    TITLE = "Honeypot Monitor CLI"
    SUB_TITLE = "Real-time honeypot activity monitoring"
    
    # Reactive attributes for status tracking
    monitoring_status = reactive("Disconnected")
    irc_status = reactive("Disconnected")
    
    # Key bindings for navigation
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "force_quit", "Force Quit", priority=True),
        Binding("escape", "quit", "Quit", priority=True),
        Binding("d", "show_dashboard", "Dashboard"),
        Binding("l", "show_logs", "Logs"),
        Binding("a", "show_analysis", "Analysis"),
        Binding("s", "show_settings", "Settings"),
        Binding("h", "show_help", "Help"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def __init__(self, config=None, **kwargs):
        """Initialize the application."""
        super().__init__(**kwargs)
        self.config = config
        self.current_view = "dashboard"
        self.dashboard: Optional[Dashboard] = None
        self.log_viewer: Optional[LogViewer] = None
        self.analysis_panel: Optional[AnalysisPanel] = None
        self.settings_panel: Optional[SettingsPanel] = None
        
        # Service coordinator for backend integration
        self.service_coordinator: Optional[ServiceCoordinator] = None
        self._setup_logging()
        
        # Initialize services if config is provided
        if self.config:
            self._initialize_services()
    
    def compose(self) -> ComposeResult:
        """Create the application layout."""
        yield Header()
        
        with Container(id="main-container"):
            with Horizontal(id="content-area"):
                # Main content area - will be populated by different views
                yield Container(id="main-content")
            
            # Status bar at the bottom
            with Horizontal(id="status-bar"):
                yield Static("Monitoring: ", id="monitoring-label")
                yield Static(self.monitoring_status, id="monitoring-status")
                yield Static(" | IRC: ", id="irc-label")
                yield Static(self.irc_status, id="irc-status")
                yield Static(" | View: ", id="view-label")
                yield Static(self.current_view.title(), id="current-view")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted."""
        print("DEBUG: on_mount() called")  # Debug output
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE
        
        print("DEBUG: About to show dashboard")  # Debug output
        self.action_show_dashboard()
        print("DEBUG: Dashboard shown, now starting services in background")  # Debug output
        
        # Start services in background thread to avoid blocking TUI
        if self.service_coordinator and not self.service_coordinator.is_running:
            print("DEBUG: Starting services in background thread")  # Debug output
            import threading
            service_thread = threading.Thread(target=self._start_monitoring_services, daemon=True)
            service_thread.start()
        
        print("DEBUG: on_mount() completed")  # Debug output
    
    def action_quit(self) -> None:
        """Quit the application."""
        try:
            # Set a timeout for cleanup to prevent hanging
            import signal
            import threading
            
            def cleanup_with_timeout():
                self._cleanup_services()
            
            # Run cleanup in a separate thread with timeout
            cleanup_thread = threading.Thread(target=cleanup_with_timeout, daemon=True)
            cleanup_thread.start()
            cleanup_thread.join(timeout=3.0)  # 3 second timeout
            
            if cleanup_thread.is_alive():
                logging.warning("Cleanup timed out, forcing exit")
            
        except Exception as e:
            logging.error(f"Error during quit: {e}")
        finally:
            # Force exit regardless of cleanup status
            self.exit()
    
    def action_force_quit(self) -> None:
        """Force quit the application without cleanup."""
        logging.info("Force quit requested")
        self.exit()
    
    def action_show_dashboard(self) -> None:
        """Show the main dashboard view."""
        self.current_view = "dashboard"
        self._show_dashboard()
        self._update_view_status()
    
    def _show_dashboard(self) -> None:
        """Display the dashboard with all components."""
        main_content = self.query_one("#main-content")
        main_content.remove_children()
        
        # Create and mount dashboard only if it doesn't exist
        if self.dashboard is None:
            self.dashboard = Dashboard()
        
        main_content.mount(self.dashboard)
        
        # Sample data disabled - using real log data
        # self._populate_sample_data()
    
    def _show_log_viewer(self) -> None:
        """Display the log viewer with all components."""
        main_content = self.query_one("#main-content")
        main_content.remove_children()
        
        # Create and mount log viewer only if it doesn't exist
        if self.log_viewer is None:
            self.log_viewer = LogViewer()
        
        main_content.mount(self.log_viewer)
    
    def action_show_logs(self) -> None:
        """Show the log viewer."""
        self.current_view = "logs"
        self._show_log_viewer()
        self._update_view_status()
    
    def action_show_analysis(self) -> None:
        """Show the analysis panel."""
        self.current_view = "analysis"
        self._show_analysis_panel()
        self._update_view_status()
    
    def _show_analysis_panel(self) -> None:
        """Display the analysis panel with all components."""
        main_content = self.query_one("#main-content")
        main_content.remove_children()
        
        # Create and mount analysis panel only if it doesn't exist
        if self.analysis_panel is None:
            self.analysis_panel = AnalysisPanel()
        
        main_content.mount(self.analysis_panel)
        
        # Sample data disabled - using real analysis data
        # self._populate_sample_analysis_data()
    
    def action_show_settings(self) -> None:
        """Show the settings panel."""
        self.current_view = "settings"
        self._show_settings_panel()
        self._update_view_status()
    
    def _show_settings_panel(self) -> None:
        """Display the settings panel with all components."""
        main_content = self.query_one("#main-content")
        main_content.remove_children()
        
        # Create and mount settings panel only if it doesn't exist
        if self.settings_panel is None:
            self.settings_panel = SettingsPanel()
        
        main_content.mount(self.settings_panel)
        
        # Update IRC tester with current settings if available
        self._update_settings_panel_data()
    
    def action_show_help(self) -> None:
        """Show help information."""
        help_text = """
Honeypot Monitor CLI - Help

Key Bindings:
  q / ESC - Quit application
  Ctrl+C - Force quit (if app hangs)
  d - Dashboard view
  l - Log viewer
  a - Analysis panel
  s - Settings
  h - This help
  r - Refresh current view

Navigation:
  Use arrow keys to navigate within panels
  Tab to switch between focusable elements
  Enter to select/activate items
        """
        self._update_main_content(help_text)
    
    def action_refresh(self) -> None:
        """Refresh the current view."""
        # For now, just update the display
        if self.current_view == "dashboard":
            self.action_show_dashboard()
        elif self.current_view == "logs":
            self.action_show_logs()
        elif self.current_view == "analysis":
            self.action_show_analysis()
        elif self.current_view == "settings":
            self.action_show_settings()
    
    def _populate_sample_data(self) -> None:
        """Populate dashboard with sample data for demonstration."""
        if not self.dashboard:
            return
        
        # Add sample activities
        self.dashboard.add_activity("SSH connection from 192.168.1.100", "info")
        self.dashboard.add_activity("Login attempt with username 'admin'", "warning")
        self.dashboard.add_activity("Suspicious command executed: 'wget malware.sh'", "error")
        self.dashboard.add_activity("Connection established successfully", "success")
        
        # Add sample alerts
        self.dashboard.add_alert("Multiple failed login attempts detected", "warning")
        self.dashboard.add_alert("Potential brute force attack from 10.0.0.5", "error")
        
        # Update connection statistics
        self.dashboard.update_connection_stats(
            active=3,
            total=127,
            unique=45,
            blocked=12
        )
        
        # Update IRC status
        self.dashboard.update_irc_status(
            status="Connected",
            server="irc.freenode.net:6667",
            last_message="2 minutes ago"
        )
    
    def _populate_sample_analysis_data(self) -> None:
        """Populate analysis panel with sample data for demonstration."""
        if not self.analysis_panel:
            return
        
        from ..models.threat_assessment import ThreatAssessment
        from datetime import datetime, timedelta
        
        # Add sample threat assessments
        threats = [
            ThreatAssessment(
                severity="critical",
                category="exploitation",
                confidence=0.95,
                indicators=["Privilege escalation attempt", "Root access commands"],
                recommended_action="Immediate investigation required"
            ),
            ThreatAssessment(
                severity="high",
                category="reconnaissance",
                confidence=0.85,
                indicators=["System enumeration", "Network scanning"],
                recommended_action="Monitor closely for escalation"
            ),
            ThreatAssessment(
                severity="medium",
                category="persistence",
                confidence=0.70,
                indicators=["Crontab modification", "Startup script changes"],
                recommended_action="Review system configuration"
            )
        ]
        
        for i, threat in enumerate(threats):
            self.analysis_panel.add_threat_assessment(
                threat, 
                f"192.168.1.{100 + i}", 
                f"Sample threat description {i + 1}"
            )
        
        # Add sample patterns
        patterns = [
            {
                'type': 'brute_force_attack',
                'source_ip': '10.0.0.5',
                'severity': 'high',
                'confidence': 0.9,
                'description': 'Multiple failed login attempts detected',
                'indicators': ['15 authentication failures', 'Time span: 120s'],
                'entry_count': 15,
                'time_span': 120
            },
            {
                'type': 'reconnaissance_sequence',
                'session_id': 'sess_001',
                'source_ip': '172.16.0.10',
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'System enumeration command sequence',
                'indicators': ['5 reconnaissance commands', 'Systematic enumeration'],
                'command_count': 12,
                'recon_count': 5
            },
            {
                'type': 'repeat_offender',
                'source_ip': '192.168.100.50',
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'Persistent activity from same IP over extended period',
                'indicators': ['75 total events', 'Active for 3.2 hours'],
                'event_count': 75,
                'time_span_hours': 3.2
            }
        ]
        
        for pattern in patterns:
            self.analysis_panel.add_pattern(pattern)
    
    def _update_settings_panel_data(self) -> None:
        """Update settings panel with current configuration data."""
        if not self.settings_panel:
            return
        
        # Get current settings from the settings panel
        current_settings = self.settings_panel.get_current_settings()
        if current_settings and current_settings.irc:
            # Update IRC tester with current IRC settings
            self.settings_panel.update_irc_tester(current_settings.irc)
    
    def _update_main_content(self, content: str) -> None:
        """Update the main content area."""
        main_content = self.query_one("#main-content")
        
        # Try to find existing content widget and update it
        try:
            existing_content = main_content.query_one("#content-text")
            existing_content.update(content)
        except:
            # If no existing widget, remove all children and create new one
            main_content.remove_children()
            main_content.mount(Static(content, id="content-text"))
    
    def _update_view_status(self) -> None:
        """Update the current view indicator in the status bar."""
        view_widget = self.query_one("#current-view")
        view_widget.update(self.current_view.title())
    
    def update_monitoring_status(self, status: str) -> None:
        """Update the monitoring connection status."""
        self.monitoring_status = status
        if hasattr(self, 'query_one'):
            try:
                status_widget = self.query_one("#monitoring-status")
                status_widget.update(status)
            except:
                pass  # Widget might not be mounted yet
    
    def update_irc_status(self, status: str) -> None:
        """Update the IRC connection status."""
        self.irc_status = status
        if hasattr(self, 'query_one'):
            try:
                status_widget = self.query_one("#irc-status")
                status_widget.update(status)
            except:
                pass  # Widget might not be mounted yet
    
    def _setup_logging(self) -> None:
        """Setup logging for the application."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _initialize_services(self) -> None:
        """Initialize the service coordinator and backend services."""
        try:
            print("DEBUG: Creating ServiceCoordinator...")  # Debug output
            self.service_coordinator = ServiceCoordinator(self.config)
            print("DEBUG: ServiceCoordinator created, setting up subscriptions...")  # Debug output
            self._setup_event_subscriptions()
            print("DEBUG: Event subscriptions set up")  # Debug output
            logging.info("Services initialized successfully")
        except Exception as e:
            print(f"DEBUG: Failed to initialize services: {e}")  # Debug output
            import traceback
            traceback.print_exc()
            logging.error(f"Failed to initialize services: {e}")
            # Continue without services - TUI will show sample data
    
    def _setup_event_subscriptions(self) -> None:
        """Setup event subscriptions for real-time TUI updates."""
        if not self.service_coordinator:
            return
        
        event_manager = self.service_coordinator.event_manager
        
        # Subscribe to log entries for real-time updates
        event_manager.subscribe(EventType.LOG_ENTRY, self._handle_log_entry_event)
        
        # Subscribe to threat detection events
        event_manager.subscribe(EventType.THREAT_DETECTED, self._handle_threat_event)
        
        # Subscribe to new host events
        event_manager.subscribe(EventType.NEW_HOST, self._handle_new_host_event)
        
        # Subscribe to pattern detection events
        event_manager.subscribe(EventType.PATTERN_DETECTED, self._handle_pattern_event)
        
        # Subscribe to IRC status events
        event_manager.subscribe(EventType.IRC_CONNECTED, self._handle_irc_connected)
        event_manager.subscribe(EventType.IRC_DISCONNECTED, self._handle_irc_disconnected)
        event_manager.subscribe(EventType.IRC_ERROR, self._handle_irc_error)
        
        # Subscribe to monitoring status events
        event_manager.subscribe(EventType.MONITORING_STARTED, self._handle_monitoring_started)
        event_manager.subscribe(EventType.MONITORING_STOPPED, self._handle_monitoring_stopped)
        event_manager.subscribe(EventType.MONITORING_ERROR, self._handle_monitoring_error)
        
        # Subscribe to alert events
        event_manager.subscribe(EventType.ALERT_SENT, self._handle_alert_sent)
        
        # Subscribe to system errors
        event_manager.subscribe(EventType.SYSTEM_ERROR, self._handle_system_error)
    
    def _start_monitoring_services(self) -> None:
        """Start the monitoring services with timeout."""
        if not self.service_coordinator:
            logging.warning("No service coordinator available")
            return
        
        try:
            print("DEBUG: Starting service coordinator with timeout...")  # Debug output
            
            # Use a timeout to prevent hanging
            import signal
            import threading
            
            success = False
            exception = None
            
            def start_services():
                nonlocal success, exception
                try:
                    success = self.service_coordinator.start()
                except Exception as e:
                    exception = e
            
            # Start services in thread with timeout
            service_thread = threading.Thread(target=start_services, daemon=True)
            service_thread.start()
            service_thread.join(timeout=10.0)  # 10 second timeout
            
            if service_thread.is_alive():
                print("DEBUG: Service startup timed out after 10 seconds")  # Debug output
                self.update_monitoring_status("Startup timeout")
                return
            
            if exception:
                raise exception
                
            if success:
                print("DEBUG: Service coordinator started successfully!")  # Debug output
                self.update_monitoring_status("Connected")
                logging.info("Monitoring services started successfully")
            else:
                print("DEBUG: Service coordinator failed to start!")  # Debug output
                self.update_monitoring_status("Failed to start")
                logging.error("Failed to start monitoring services")
                
        except Exception as e:
            print(f"DEBUG: Exception starting services: {e}")  # Debug output
            import traceback
            traceback.print_exc()
            self.update_monitoring_status("Error")
            logging.error(f"Error starting monitoring services: {e}")
    
    def _cleanup_services(self) -> None:
        """Cleanup services on application exit."""
        if self.service_coordinator:
            try:
                self.service_coordinator.shutdown()
                logging.info("Services cleaned up successfully")
            except Exception as e:
                logging.error(f"Error cleaning up services: {e}")
    
    def _handle_log_entry_event(self, event: Event) -> None:
        """Handle new log entry events."""
        try:
            print(f"DEBUG: Received log entry event!")  # Debug output
            log_entry = event.data["log_entry"]
            print(f"DEBUG: Log entry - Type: {log_entry.event_type}, IP: {log_entry.source_ip}")  # Debug output
            
            # Update dashboard if visible
            if self.current_view == "dashboard" and self.dashboard:
                print(f"DEBUG: Updating dashboard with log entry")  # Debug output
                self._update_dashboard_with_log_entry(log_entry)
            
            # Update log viewer if visible
            if self.current_view == "logs" and self.log_viewer:
                print(f"DEBUG: Updating log viewer with log entry")  # Debug output
                self._update_log_viewer_with_entry(log_entry)
                
        except Exception as e:
            print(f"DEBUG: Error handling log entry event: {e}")  # Debug output
            logging.error(f"Error handling log entry event: {e}")
    
    def _handle_threat_event(self, event: Event) -> None:
        """Handle threat detection events."""
        try:
            threat = event.data["threat"]
            source_ip = event.data["source_ip"]
            log_entry = event.data["log_entry"]
            
            # Update dashboard with threat alert
            if self.current_view == "dashboard" and self.dashboard:
                severity_map = {"low": "info", "medium": "warning", "high": "error", "critical": "error"}
                alert_type = severity_map.get(threat.severity, "warning")
                
                message = f"Threat detected from {source_ip}: {threat.category}"
                self.dashboard.add_alert(message, alert_type)
            
            # Update analysis panel if visible
            if self.current_view == "analysis" and self.analysis_panel:
                self.analysis_panel.add_threat_assessment(threat, source_ip, threat.recommended_action)
                
        except Exception as e:
            logging.error(f"Error handling threat event: {e}")
    
    def _handle_new_host_event(self, event: Event) -> None:
        """Handle new host detection events."""
        try:
            source_ip = event.data["source_ip"]
            first_seen = event.data["first_seen"]
            
            # Update dashboard
            if self.current_view == "dashboard" and self.dashboard:
                message = f"New host detected: {source_ip}"
                self.dashboard.add_activity(message, "info")
                
        except Exception as e:
            logging.error(f"Error handling new host event: {e}")
    
    def _handle_pattern_event(self, event: Event) -> None:
        """Handle pattern detection events."""
        try:
            pattern = event.data["pattern"]
            
            # Update analysis panel if visible
            if self.current_view == "analysis" and self.analysis_panel:
                self.analysis_panel.add_pattern(pattern)
            
            # Update dashboard with pattern alert
            if self.current_view == "dashboard" and self.dashboard:
                severity_map = {"low": "info", "medium": "warning", "high": "error", "critical": "error"}
                alert_type = severity_map.get(pattern.get("severity", "medium"), "warning")
                
                message = f"Pattern detected: {pattern.get('type', 'unknown')}"
                self.dashboard.add_alert(message, alert_type)
                
        except Exception as e:
            logging.error(f"Error handling pattern event: {e}")
    
    def _handle_irc_connected(self, event: Event) -> None:
        """Handle IRC connection events."""
        self.update_irc_status("Connected")
        
        # Update dashboard IRC status
        if self.dashboard:
            self.dashboard.update_irc_status(
                status="Connected",
                server=f"{self.config.irc.server}:{self.config.irc.port}" if self.config else "Unknown",
                last_message="Just connected"
            )
    
    def _handle_irc_disconnected(self, event: Event) -> None:
        """Handle IRC disconnection events."""
        self.update_irc_status("Disconnected")
        
        # Update dashboard IRC status
        if self.dashboard:
            self.dashboard.update_irc_status(
                status="Disconnected",
                server=f"{self.config.irc.server}:{self.config.irc.port}" if self.config else "Unknown",
                last_message="Connection lost"
            )
    
    def _handle_irc_error(self, event: Event) -> None:
        """Handle IRC error events."""
        error_msg = event.data.get("message", "Unknown error")
        self.update_irc_status(f"Error: {error_msg}")
        
        # Update dashboard IRC status
        if self.dashboard:
            self.dashboard.update_irc_status(
                status="Error",
                server=f"{self.config.irc.server}:{self.config.irc.port}" if self.config else "Unknown",
                last_message=f"Error: {error_msg}"
            )
    
    def _handle_monitoring_started(self, event: Event) -> None:
        """Handle monitoring started events."""
        self.update_monitoring_status("Connected")
    
    def _handle_monitoring_stopped(self, event: Event) -> None:
        """Handle monitoring stopped events."""
        self.update_monitoring_status("Disconnected")
    
    def _handle_monitoring_error(self, event: Event) -> None:
        """Handle monitoring error events."""
        error_msg = event.data.get("message", "Unknown error")
        self.update_monitoring_status(f"Error: {error_msg}")
    
    def _handle_alert_sent(self, event: Event) -> None:
        """Handle alert sent events."""
        try:
            alert = event.data["alert"]
            success = event.data["success"]
            
            if success and self.dashboard:
                message = f"Alert sent: {alert.alert_type} for {alert.source_ip}"
                self.dashboard.add_activity(message, "success")
                
        except Exception as e:
            logging.error(f"Error handling alert sent event: {e}")
    
    def _handle_system_error(self, event: Event) -> None:
        """Handle system error events."""
        error_msg = event.data.get("error_message", "Unknown system error")
        logging.error(f"System error: {error_msg}")
        
        # Show error in dashboard if visible
        if self.current_view == "dashboard" and self.dashboard:
            self.dashboard.add_alert(f"System error: {error_msg}", "error")
    
    def _update_dashboard_with_log_entry(self, log_entry: LogEntry) -> None:
        """Update dashboard with new log entry."""
        try:
            print(f"DEBUG: _update_dashboard_with_log_entry called")  # Debug output
            
            # Determine activity type based on log entry
            activity_type = "info"
            if log_entry.event_type == "authentication":
                activity_type = "warning" if "failed" in log_entry.message.lower() else "success"
            elif log_entry.event_type == "command":
                activity_type = "info"
            elif log_entry.threat_level:
                threat_map = {"low": "info", "medium": "warning", "high": "error", "critical": "error"}
                activity_type = threat_map.get(log_entry.threat_level, "info")
            
            print(f"DEBUG: Activity type determined: {activity_type}")  # Debug output
            
            # Format message
            message = f"{log_entry.source_ip}: {log_entry.message}"
            if log_entry.command:
                message = f"{log_entry.source_ip}: {log_entry.command}"
            
            print(f"DEBUG: Adding activity to dashboard: {message[:50]}...")  # Debug output
            self.dashboard.add_activity(message, activity_type)
            
            # Update connection statistics (simplified)
            if hasattr(self, '_connection_stats'):
                self._connection_stats['total'] += 1
            else:
                self._connection_stats = {'active': 1, 'total': 1, 'unique': 1, 'blocked': 0}
            
            self.dashboard.update_connection_stats(**self._connection_stats)
            
        except Exception as e:
            logging.error(f"Error updating dashboard with log entry: {e}")
    
    def _update_log_viewer_with_entry(self, log_entry: LogEntry) -> None:
        """Update log viewer with new log entry."""
        try:
            # Add entry to log viewer
            self.log_viewer.add_log_entry(log_entry)
        except Exception as e:
            logging.error(f"Error updating log viewer with entry: {e}")


def main():
    """Entry point for the TUI application."""
    app = HoneypotMonitorApp()
    app.run()


if __name__ == "__main__":
    main()