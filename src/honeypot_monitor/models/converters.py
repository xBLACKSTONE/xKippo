"""
Model conversion utilities for honeypot monitoring.
"""

from datetime import datetime
from typing import List, Optional
from .log_entry import LogEntry
from .session import Session
from .threat_assessment import ThreatAssessment
from .irc_alert import IRCAlert


class ModelConverter:
    """Utility class for converting between related model types."""
    
    @staticmethod
    def threat_to_irc_alert(threat: ThreatAssessment, source_ip: str, 
                           context_message: Optional[str] = None) -> IRCAlert:
        """
        Convert a ThreatAssessment to an IRCAlert.
        
        Args:
            threat: ThreatAssessment to convert
            source_ip: IP address associated with the threat
            context_message: Optional context message to include
            
        Returns:
            IRCAlert based on the threat assessment
        """
        # Determine alert type based on threat category
        alert_type_map = {
            'reconnaissance': 'interesting_traffic',
            'exploitation': 'high_threat',
            'persistence': 'high_threat',
            'lateral_movement': 'high_threat',
            'exfiltration': 'high_threat',
            'unknown': 'interesting_traffic'
        }
        
        alert_type = alert_type_map.get(threat.category, 'interesting_traffic')
        
        # Create message from threat data
        message_parts = []
        if context_message:
            message_parts.append(context_message)
        
        message_parts.append(f"Threat detected: {threat.category}")
        
        if threat.indicators:
            indicators_str = ", ".join(threat.indicators[:3])  # Limit to first 3 indicators
            if len(threat.indicators) > 3:
                indicators_str += f" (+{len(threat.indicators) - 3} more)"
            message_parts.append(f"Indicators: {indicators_str}")
        
        if threat.recommended_action:
            message_parts.append(f"Action: {threat.recommended_action}")
        
        message = " | ".join(message_parts)
        
        return IRCAlert(
            alert_type=alert_type,
            timestamp=datetime.now(),
            source_ip=source_ip,
            message=message,
            severity=threat.severity
        )
    
    @staticmethod
    def log_entry_to_threat_assessment(log_entry: LogEntry, 
                                     additional_indicators: Optional[List[str]] = None) -> ThreatAssessment:
        """
        Convert a LogEntry to a basic ThreatAssessment.
        
        Args:
            log_entry: LogEntry to analyze
            additional_indicators: Optional additional threat indicators
            
        Returns:
            ThreatAssessment based on the log entry
        """
        indicators = []
        
        # Add indicators based on log entry content
        if log_entry.command:
            indicators.append(f"Command: {log_entry.command}")
        
        if log_entry.file_path:
            indicators.append(f"File access: {log_entry.file_path}")
        
        indicators.append(f"Event type: {log_entry.event_type}")
        
        if additional_indicators:
            indicators.extend(additional_indicators)
        
        # Determine category based on event type and content
        category = ModelConverter._determine_threat_category(log_entry)
        
        # Determine severity based on existing threat_level or default
        severity = log_entry.threat_level or 'low'
        
        # Set confidence based on available data
        confidence = 0.6 if log_entry.command or log_entry.file_path else 0.3
        
        return ThreatAssessment(
            severity=severity,
            category=category,
            confidence=confidence,
            indicators=indicators,
            recommended_action=ModelConverter._get_recommended_action(category, severity)
        )
    
    @staticmethod
    def session_to_threat_assessment(session: Session) -> ThreatAssessment:
        """
        Convert a Session to a ThreatAssessment based on session activity.
        
        Args:
            session: Session to analyze
            
        Returns:
            ThreatAssessment based on session activity
        """
        indicators = []
        
        # Add indicators based on session data
        if session.commands:
            indicators.append(f"Commands executed: {len(session.commands)}")
            # Add some example commands
            example_commands = session.commands[:3]
            indicators.append(f"Sample commands: {', '.join(example_commands)}")
        
        if session.files_accessed:
            indicators.append(f"Files accessed: {len(session.files_accessed)}")
            # Add some example files
            example_files = session.files_accessed[:3]
            indicators.append(f"Sample files: {', '.join(example_files)}")
        
        duration = session.duration()
        if duration:
            indicators.append(f"Session duration: {duration:.0f} seconds")
        
        # Determine category based on activity patterns
        category = ModelConverter._determine_session_threat_category(session)
        
        # Use existing threat score or calculate based on activity
        if session.threat_score > 0:
            severity = ModelConverter._score_to_severity(session.threat_score)
            confidence = session.threat_score
        else:
            severity, confidence = ModelConverter._calculate_session_threat(session)
        
        return ThreatAssessment(
            severity=severity,
            category=category,
            confidence=confidence,
            indicators=indicators,
            recommended_action=ModelConverter._get_recommended_action(category, severity)
        )
    
    @staticmethod
    def _determine_threat_category(log_entry: LogEntry) -> str:
        """Determine threat category from log entry."""
        if log_entry.event_type in ['login', 'authentication']:
            return 'reconnaissance'
        elif log_entry.event_type == 'command':
            if log_entry.command:
                # Check for exploitation commands
                exploit_commands = ['wget', 'curl', 'nc', 'netcat', 'python', 'perl', 'bash']
                if any(cmd in log_entry.command.lower() for cmd in exploit_commands):
                    return 'exploitation'
            return 'reconnaissance'
        elif log_entry.event_type == 'file_access':
            # File access could be reconnaissance or persistence
            if log_entry.file_path and any(path in log_entry.file_path for path in ['/etc/', '/root/', '/.ssh/']):
                return 'persistence'
            return 'reconnaissance'
        else:
            return 'unknown'
    
    @staticmethod
    def _determine_session_threat_category(session: Session) -> str:
        """Determine threat category from session activity."""
        if not session.commands:
            return 'reconnaissance'
        
        # Analyze commands for threat patterns
        commands_str = ' '.join(session.commands).lower()
        
        if any(cmd in commands_str for cmd in ['wget', 'curl', 'python', 'perl', 'bash -i']):
            return 'exploitation'
        elif any(cmd in commands_str for cmd in ['crontab', 'systemctl', 'service', '.bashrc', '.profile']):
            return 'persistence'
        elif len(session.commands) > 10:  # High activity
            return 'reconnaissance'
        else:
            return 'reconnaissance'
    
    @staticmethod
    def _calculate_session_threat(session: Session) -> tuple[str, float]:
        """Calculate threat severity and confidence for a session."""
        score = 0.0
        
        # Score based on number of commands
        if session.command_count() > 20:
            score += 0.4
        elif session.command_count() > 10:
            score += 0.2
        elif session.command_count() > 5:
            score += 0.1
        
        # Score based on file access
        if session.file_access_count() > 10:
            score += 0.3
        elif session.file_access_count() > 5:
            score += 0.2
        elif session.file_access_count() > 0:
            score += 0.1
        
        # Score based on session duration
        duration = session.duration()
        if duration and duration > 3600:  # More than 1 hour
            score += 0.2
        elif duration and duration > 1800:  # More than 30 minutes
            score += 0.1
        
        # Ensure score is within bounds
        score = min(score, 1.0)
        
        severity = ModelConverter._score_to_severity(score)
        return severity, score
    
    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert numeric score to severity level."""
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.3:
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _get_recommended_action(category: str, severity: str) -> str:
        """Get recommended action based on category and severity."""
        if severity == 'critical':
            return 'Immediate investigation required - block IP and analyze activity'
        elif severity == 'high':
            if category == 'exploitation':
                return 'Block IP and investigate exploitation attempts'
            elif category == 'persistence':
                return 'Check for persistence mechanisms and monitor closely'
            else:
                return 'Monitor closely and consider blocking if activity continues'
        elif severity == 'medium':
            return 'Monitor activity and log for analysis'
        else:
            return 'Continue monitoring'