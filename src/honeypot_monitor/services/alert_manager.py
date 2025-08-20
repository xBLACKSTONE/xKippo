"""
Alert management service that integrates threat analysis with IRC notifications.
"""

import logging
from typing import List, Dict, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from collections import defaultdict

from ..models.log_entry import LogEntry
from ..models.threat_assessment import ThreatAssessment
from ..models.irc_alert import IRCAlert
from .threat_analyzer import ThreatAnalyzer
from .irc_notifier import IRCNotifier


logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manages the integration between threat analysis and IRC notifications.
    
    Handles alert formatting, rate limiting, and notification delivery
    for different types of security events.
    """
    
    def __init__(self, 
                 threat_analyzer: ThreatAnalyzer,
                 irc_notifier: Optional[IRCNotifier] = None,
                 alert_threshold: str = 'medium',
                 rate_limit_window: int = 300,  # 5 minutes
                 max_alerts_per_ip: int = 3,
                 max_duplicate_alerts: int = 1):
        """
        Initialize the alert manager.
        
        Args:
            threat_analyzer: ThreatAnalyzer instance
            irc_notifier: IRCNotifier instance (optional)
            alert_threshold: Minimum severity level for IRC alerts
            rate_limit_window: Time window for rate limiting (seconds)
            max_alerts_per_ip: Maximum alerts per IP in rate limit window
            max_duplicate_alerts: Maximum duplicate alerts for same threat
        """
        self.threat_analyzer = threat_analyzer
        self.irc_notifier = irc_notifier
        self.alert_threshold = alert_threshold
        self.rate_limit_window = rate_limit_window
        self.max_alerts_per_ip = max_alerts_per_ip
        self.max_duplicate_alerts = max_duplicate_alerts
        
        # Alert tracking for rate limiting and deduplication
        self.recent_alerts: Dict[str, List[datetime]] = defaultdict(list)
        self.alert_history: List[IRCAlert] = []
        self.seen_hosts: Set[str] = set()
        
        # Callbacks for different alert types
        self.on_new_host_callback: Optional[Callable[[str, datetime], None]] = None
        self.on_threat_callback: Optional[Callable[[ThreatAssessment, str], None]] = None
        self.on_interesting_traffic_callback: Optional[Callable[[str, str], None]] = None
        
        # Severity level mapping
        self.severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        self.threshold_level = self.severity_levels.get(alert_threshold, 2)
    
    def process_log_entry(self, entry: LogEntry) -> List[IRCAlert]:
        """
        Process a log entry and generate appropriate alerts.
        
        Args:
            entry: LogEntry to process
            
        Returns:
            List of IRCAlert objects generated
        """
        alerts = []
        
        # Check for new host
        if entry.source_ip not in self.seen_hosts:
            self.seen_hosts.add(entry.source_ip)
            new_host_alert = self._create_new_host_alert(entry.source_ip, entry.timestamp)
            if new_host_alert:
                alerts.append(new_host_alert)
        
        # Analyze threat level
        threat_assessment = self.threat_analyzer.analyze_entry(entry)
        if self._should_alert_for_threat(threat_assessment):
            threat_alert = self._create_threat_alert(entry.source_ip, threat_assessment)
            if threat_alert:
                alerts.append(threat_alert)
        
        # Check for interesting traffic patterns
        interesting_alert = self._check_interesting_traffic(entry)
        if interesting_alert:
            alerts.append(interesting_alert)
        
        # Apply custom rules
        custom_alerts = self.threat_analyzer.apply_custom_rules(entry)
        for custom_alert in custom_alerts:
            if self._should_alert_for_custom_rule(custom_alert):
                irc_alert = self._create_custom_rule_alert(entry.source_ip, custom_alert)
                if irc_alert:
                    alerts.append(irc_alert)
        
        # Send alerts via IRC if configured
        sent_alerts = []
        for alert in alerts:
            if self._should_send_alert(alert):
                if self.irc_notifier and self.irc_notifier.send_alert(alert):
                    sent_alerts.append(alert)
                    self._track_sent_alert(alert)
                    logger.info(f"Sent IRC alert: {alert.alert_type} for {alert.source_ip}")
                else:
                    logger.warning(f"Failed to send IRC alert: {alert.alert_type} for {alert.source_ip}")
        
        # Store alerts in history
        self.alert_history.extend(alerts)
        self._cleanup_old_alerts()
        
        return sent_alerts
    
    def process_pattern_detection(self, entries: List[LogEntry]) -> List[IRCAlert]:
        """
        Process pattern detection results and generate alerts.
        
        Args:
            entries: List of LogEntry objects to analyze for patterns
            
        Returns:
            List of IRCAlert objects generated from patterns
        """
        alerts = []
        
        # Detect patterns using threat analyzer
        patterns = self.threat_analyzer.detect_patterns(entries)
        
        for pattern in patterns:
            # Create alert based on pattern type
            if pattern['type'] == 'brute_force_attack':
                alert = self._create_brute_force_alert(pattern)
            elif pattern['type'] == 'reconnaissance_sequence':
                alert = self._create_reconnaissance_alert(pattern)
            elif pattern['type'] == 'privilege_escalation_sequence':
                alert = self._create_privilege_escalation_alert(pattern)
            elif pattern['type'] == 'burst_activity':
                alert = self._create_burst_activity_alert(pattern)
            elif pattern['type'] == 'repeat_offender':
                alert = self._create_repeat_offender_alert(pattern)
            else:
                alert = self._create_generic_pattern_alert(pattern)
            
            if alert and self._should_send_alert(alert):
                alerts.append(alert)
                
                # Send via IRC if configured
                if self.irc_notifier and self.irc_notifier.send_alert(alert):
                    self._track_sent_alert(alert)
                    logger.info(f"Sent pattern alert: {pattern['type']}")
        
        return alerts
    
    def set_callbacks(self,
                     on_new_host: Optional[Callable[[str, datetime], None]] = None,
                     on_threat: Optional[Callable[[ThreatAssessment, str], None]] = None,
                     on_interesting_traffic: Optional[Callable[[str, str], None]] = None) -> None:
        """
        Set callback functions for different alert types.
        
        Args:
            on_new_host: Called when a new host is detected
            on_threat: Called when a threat is detected
            on_interesting_traffic: Called when interesting traffic is detected
        """
        self.on_new_host_callback = on_new_host
        self.on_threat_callback = on_threat
        self.on_interesting_traffic_callback = on_interesting_traffic
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about alerts generated.
        
        Returns:
            Dictionary with alert statistics
        """
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)
        
        recent_alerts = [a for a in self.alert_history if a.timestamp > last_hour]
        daily_alerts = [a for a in self.alert_history if a.timestamp > last_day]
        
        stats = {
            'total_alerts': len(self.alert_history),
            'alerts_last_hour': len(recent_alerts),
            'alerts_last_day': len(daily_alerts),
            'unique_hosts_seen': len(self.seen_hosts),
            'alert_types': {},
            'severity_distribution': {}
        }
        
        # Count by alert type
        for alert in self.alert_history:
            stats['alert_types'][alert.alert_type] = stats['alert_types'].get(alert.alert_type, 0) + 1
            stats['severity_distribution'][alert.severity] = stats['severity_distribution'].get(alert.severity, 0) + 1
        
        return stats
    
    def _create_new_host_alert(self, source_ip: str, first_seen: datetime) -> Optional[IRCAlert]:
        """Create alert for new host detection."""
        if not self._should_rate_limit_ip(source_ip, 'new_host'):
            alert = IRCAlert.create_new_host_alert(source_ip, first_seen)
            
            # Call callback if set
            if self.on_new_host_callback:
                self.on_new_host_callback(source_ip, first_seen)
            
            return alert
        return None
    
    def _create_threat_alert(self, source_ip: str, threat_assessment: ThreatAssessment) -> Optional[IRCAlert]:
        """Create alert for threat detection."""
        if not self._should_rate_limit_ip(source_ip, 'threat'):
            # Format threat description
            description = f"{threat_assessment.category.title()} threat detected"
            if threat_assessment.indicators:
                description += f": {', '.join(threat_assessment.indicators[:2])}"
            
            alert = IRCAlert.create_threat_alert(source_ip, description, threat_assessment.severity)
            
            # Call callback if set
            if self.on_threat_callback:
                self.on_threat_callback(threat_assessment, source_ip)
            
            return alert
        return None
    
    def _check_interesting_traffic(self, entry: LogEntry) -> Optional[IRCAlert]:
        """Check for interesting traffic patterns."""
        interesting_patterns = [
            # Unusual commands
            ('wget', 'Download attempt detected'),
            ('curl', 'HTTP request detected'),
            ('python -c', 'Python one-liner executed'),
            ('base64', 'Base64 encoding/decoding detected'),
            ('nc -l', 'Netcat listener started'),
            ('ssh-keygen', 'SSH key generation detected'),
            ('crontab', 'Cron job modification detected'),
        ]
        
        if entry.command:
            for pattern, description in interesting_patterns:
                if pattern in entry.command.lower():
                    if not self._should_rate_limit_ip(entry.source_ip, 'interesting'):
                        alert = IRCAlert.create_interesting_traffic_alert(
                            entry.source_ip, 
                            f"{description}: {entry.command[:100]}"
                        )
                        
                        # Call callback if set
                        if self.on_interesting_traffic_callback:
                            self.on_interesting_traffic_callback(entry.source_ip, description)
                        
                        return alert
        
        return None
    
    def _create_custom_rule_alert(self, source_ip: str, custom_alert: Dict[str, Any]) -> Optional[IRCAlert]:
        """Create alert from custom rule detection."""
        if not self._should_rate_limit_ip(source_ip, 'custom'):
            return IRCAlert(
                alert_type='high_threat',
                timestamp=custom_alert['timestamp'],
                source_ip=source_ip,
                message=custom_alert['description'],
                severity=custom_alert['severity']
            )
        return None
    
    def _create_brute_force_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create alert for brute force pattern."""
        return IRCAlert(
            alert_type='high_threat',
            timestamp=datetime.now(),
            source_ip=pattern['source_ip'],
            message=f"Brute force attack: {pattern['entry_count']} attempts in {pattern['time_span']:.0f}s",
            severity='high'
        )
    
    def _create_reconnaissance_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create alert for reconnaissance pattern."""
        return IRCAlert(
            alert_type='interesting_traffic',
            timestamp=datetime.now(),
            source_ip=pattern['source_ip'],
            message=f"Reconnaissance detected: {pattern['recon_count']} enumeration commands",
            severity='medium'
        )
    
    def _create_privilege_escalation_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create alert for privilege escalation pattern."""
        return IRCAlert(
            alert_type='high_threat',
            timestamp=datetime.now(),
            source_ip=pattern['source_ip'],
            message=f"Privilege escalation: {pattern['priv_count']} escalation attempts",
            severity='high'
        )
    
    def _create_burst_activity_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create alert for burst activity pattern."""
        return IRCAlert(
            alert_type='interesting_traffic',
            timestamp=datetime.now(),
            source_ip='multiple',  # Burst activity may involve multiple IPs
            message=f"Burst activity: {pattern['event_count']} events in 5 minutes",
            severity='medium'
        )
    
    def _create_repeat_offender_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create alert for repeat offender pattern."""
        return IRCAlert(
            alert_type='interesting_traffic',
            timestamp=datetime.now(),
            source_ip=pattern['source_ip'],
            message=f"Repeat offender: {pattern['event_count']} events over {pattern['time_span_hours']:.1f}h",
            severity='medium'
        )
    
    def _create_generic_pattern_alert(self, pattern: Dict[str, Any]) -> IRCAlert:
        """Create generic alert for unknown pattern types."""
        return IRCAlert(
            alert_type='interesting_traffic',
            timestamp=datetime.now(),
            source_ip=pattern.get('source_ip', 'unknown'),
            message=f"Pattern detected: {pattern['type']} - {pattern.get('description', 'No description')}",
            severity=pattern.get('severity', 'low')
        )
    
    def _should_alert_for_threat(self, threat_assessment: ThreatAssessment) -> bool:
        """Check if threat assessment meets alert threshold."""
        threat_level = self.severity_levels.get(threat_assessment.severity, 0)
        return threat_level >= self.threshold_level
    
    def _should_alert_for_custom_rule(self, custom_alert: Dict[str, Any]) -> bool:
        """Check if custom rule alert meets threshold."""
        alert_level = self.severity_levels.get(custom_alert.get('severity', 'low'), 0)
        return alert_level >= self.threshold_level
    
    def _should_send_alert(self, alert: IRCAlert) -> bool:
        """Check if alert should be sent based on rate limiting and deduplication."""
        # Check if we have IRC notifier configured
        if not self.irc_notifier or not self.irc_notifier.is_connected():
            return False
        
        # Check severity threshold
        alert_level = self.severity_levels.get(alert.severity, 0)
        if alert_level < self.threshold_level:
            return False
        
        # Check for duplicate alerts
        if self._is_duplicate_alert(alert):
            return False
        
        return True
    
    def _should_rate_limit_ip(self, source_ip: str, alert_type: str) -> bool:
        """Check if IP should be rate limited for specific alert type."""
        key = f"{source_ip}:{alert_type}"
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.rate_limit_window)
        
        # Clean old entries
        self.recent_alerts[key] = [ts for ts in self.recent_alerts[key] if ts > cutoff]
        
        # Check if we've exceeded the limit
        if len(self.recent_alerts[key]) >= self.max_alerts_per_ip:
            return True
        
        # Add current timestamp
        self.recent_alerts[key].append(now)
        return False
    
    def _is_duplicate_alert(self, alert: IRCAlert) -> bool:
        """Check if alert is a duplicate of recent alerts."""
        cutoff = datetime.now() - timedelta(seconds=self.rate_limit_window)
        
        similar_alerts = [
            a for a in self.alert_history
            if (a.timestamp > cutoff and
                a.alert_type == alert.alert_type and
                a.source_ip == alert.source_ip and
                a.severity == alert.severity)
        ]
        
        return len(similar_alerts) >= self.max_duplicate_alerts
    
    def _track_sent_alert(self, alert: IRCAlert) -> None:
        """Track that an alert was sent."""
        alert.mark_as_sent()
    
    def _cleanup_old_alerts(self) -> None:
        """Clean up old alerts to prevent memory bloat."""
        cutoff = datetime.now() - timedelta(days=7)  # Keep 7 days of history
        self.alert_history = [a for a in self.alert_history if a.timestamp > cutoff]
        
        # Clean up rate limiting data
        cutoff_rate_limit = datetime.now() - timedelta(seconds=self.rate_limit_window * 2)
        for key in list(self.recent_alerts.keys()):
            self.recent_alerts[key] = [ts for ts in self.recent_alerts[key] if ts > cutoff_rate_limit]
            if not self.recent_alerts[key]:
                del self.recent_alerts[key]