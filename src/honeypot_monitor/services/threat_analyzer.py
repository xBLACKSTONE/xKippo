"""
Threat analysis engine for honeypot monitoring.
"""

import re
from typing import List, Dict, Any, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from ..interfaces.analyzer_interface import AnalyzerInterface
from ..models.log_entry import LogEntry
from ..models.threat_assessment import ThreatAssessment
from ..config.settings import AnalysisSettings


class ThreatAnalyzer(AnalyzerInterface):
    """
    Threat analysis engine that categorizes and scores honeypot activity.
    
    Implements configurable detection rules for threat categorization,
    severity scoring, and pattern detection.
    """
    
    def __init__(self, settings: AnalysisSettings):
        """
        Initialize the threat analyzer with configuration settings.
        
        Args:
            settings: Analysis configuration settings
        """
        self.settings = settings
        self._ip_activity_tracker: Dict[str, List[LogEntry]] = defaultdict(list)
        self._session_tracker: Dict[str, List[LogEntry]] = defaultdict(list)
        self._command_patterns = self._initialize_command_patterns()
        self._threat_indicators = self._initialize_threat_indicators()
        
    def _initialize_command_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize command patterns for threat detection."""
        return {
            # Reconnaissance patterns
            'system_enumeration': {
                'patterns': [
                    r'\b(whoami|id|uname|hostname|ps|netstat|ifconfig|ip\s+addr)\b',
                    r'\b(cat\s+/etc/(passwd|shadow|hosts|issue))\b',
                    r'\b(ls\s+(-la\s+)?/)\b',
                    r'\b(find\s+/.*-name)\b'
                ],
                'category': 'reconnaissance',
                'severity': 'low',
                'confidence': 0.7
            },
            'network_scanning': {
                'patterns': [
                    r'\b(nmap|masscan|zmap)\b',
                    r'\b(nc|netcat).*-[zv]\b',
                    r'\b(telnet|ssh).*\d+\.\d+\.\d+\.\d+\b'
                ],
                'category': 'reconnaissance',
                'severity': 'medium',
                'confidence': 0.8
            },
            
            # Exploitation patterns
            'privilege_escalation': {
                'patterns': [
                    r'\b(sudo|su)\s+',
                    r'\b(chmod\s+777|chmod\s+\+s)\b',
                    r'\b(/etc/sudoers|visudo)\b',
                    r'\b(passwd|chpasswd)\b'
                ],
                'category': 'exploitation',
                'severity': 'high',
                'confidence': 0.9
            },
            'malware_download': {
                'patterns': [
                    r'\b(wget|curl).*http[s]?://\b',
                    r'\b(ftp|tftp).*get\b',
                    r'\b(python|perl|ruby).*-c.*http\b',
                    r'\b(base64\s+-d|xxd\s+-r)\b'
                ],
                'category': 'exploitation',
                'severity': 'high',
                'confidence': 0.85
            },
            
            # Persistence patterns
            'backdoor_creation': {
                'patterns': [
                    r'\bcrontab\b',
                    r'\bat\s+now\b',
                    r'/etc/rc\.local',
                    r'\.bashrc',
                    r'\.profile',
                    r'\bsystemctl.*enable\b',
                    r'\bservice.*enable\b',
                    r'\bssh-keygen\b',
                    r'authorized_keys'
                ],
                'category': 'persistence',
                'severity': 'critical',
                'confidence': 0.9
            },
            'file_modification': {
                'patterns': [
                    r'echo.*>>',
                    r'cat.*>',
                    r'\b(vi|vim|nano|emacs)\s+/etc/',
                    r'\b(cp|mv).*/(bin|sbin|usr/bin)'
                ],
                'category': 'persistence',
                'severity': 'medium',
                'confidence': 0.7
            },
            
            # Lateral movement patterns
            'lateral_movement': {
                'patterns': [
                    r'\b(ssh|scp|rsync).*@.*\b',
                    r'\b(ssh|scp|rsync).*\d+\.\d+\.\d+\.\d+\b',
                    r'\b(mount|smbclient)\b',
                    r'\b(arp|ping)\s+\d+\.\d+\.\d+\.\d+\b',
                    r'\bping\s+\d+\.\d+\.\d+\.\d+\b',
                    r'\barp\s+-a\b'
                ],
                'category': 'lateral_movement',
                'severity': 'high',
                'confidence': 0.8
            }
        }
    
    def _initialize_threat_indicators(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat indicators for various attack types."""
        return {
            'brute_force_indicators': {
                'failed_login_threshold': 5,
                'time_window_minutes': 10,
                'severity': 'medium',
                'confidence': 0.8
            },
            'rapid_commands': {
                'command_threshold': 10,
                'time_window_minutes': 2,
                'severity': 'medium',
                'confidence': 0.7
            },
            'suspicious_files': {
                'patterns': [
                    r'\.sh$', r'\.py$', r'\.pl$', r'\.exe$',
                    r'backdoor', r'shell', r'exploit', r'payload'
                ],
                'severity': 'high',
                'confidence': 0.8
            },
            'known_malicious_ips': {
                # This would typically be loaded from external threat feeds
                'ips': set(),
                'severity': 'critical',
                'confidence': 0.95
            }
        }
    
    def analyze_entry(self, entry: LogEntry) -> ThreatAssessment:
        """
        Analyze a single log entry for threats.
        
        Args:
            entry: LogEntry to analyze
            
        Returns:
            ThreatAssessment result
        """
        # Track the entry for pattern analysis
        self._track_entry(entry)
        
        # Initialize assessment with default values
        severity = 'low'
        category = 'unknown'
        confidence = 0.5
        indicators = []
        recommended_action = 'Monitor activity'
        
        # Analyze command patterns if command is present
        if entry.command:
            command_assessment = self._analyze_command_patterns(entry.command)
            if command_assessment:
                severity = command_assessment['severity']
                category = command_assessment['category']
                confidence = command_assessment['confidence']
                indicators.extend(command_assessment['indicators'])
        
        # Analyze event type patterns
        event_assessment = self._analyze_event_type(entry)
        if event_assessment and event_assessment['severity_score'] > self._get_severity_score(severity):
            severity = event_assessment['severity']
            category = event_assessment['category']
            confidence = max(confidence, event_assessment['confidence'])
            indicators.extend(event_assessment['indicators'])
        
        # Check for IP-based threats
        ip_assessment = self._analyze_ip_behavior(entry)
        if ip_assessment and ip_assessment['severity_score'] > self._get_severity_score(severity):
            severity = ip_assessment['severity']
            confidence = max(confidence, ip_assessment['confidence'])
            indicators.extend(ip_assessment['indicators'])
        
        # Determine recommended action based on severity
        if severity == 'critical':
            recommended_action = 'Immediate investigation required - potential active threat'
        elif severity == 'high':
            recommended_action = 'Investigate activity - likely malicious behavior'
        elif severity == 'medium':
            recommended_action = 'Review activity - suspicious patterns detected'
        
        return ThreatAssessment(
            severity=severity,
            category=category,
            confidence=confidence,
            indicators=indicators,
            recommended_action=recommended_action
        )
    
    def _track_entry(self, entry: LogEntry) -> None:
        """Track log entry for pattern analysis."""
        # Track by IP address
        self._ip_activity_tracker[entry.source_ip].append(entry)
        
        # Track by session
        self._session_tracker[entry.session_id].append(entry)
        
        # Cleanup old entries to prevent memory issues
        self._cleanup_old_entries()
    
    def _cleanup_old_entries(self) -> None:
        """Remove old entries to prevent memory bloat."""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Clean IP tracker
        for ip in list(self._ip_activity_tracker.keys()):
            self._ip_activity_tracker[ip] = [
                entry for entry in self._ip_activity_tracker[ip]
                if entry.timestamp > cutoff_time
            ]
            if not self._ip_activity_tracker[ip]:
                del self._ip_activity_tracker[ip]
        
        # Clean session tracker
        for session_id in list(self._session_tracker.keys()):
            self._session_tracker[session_id] = [
                entry for entry in self._session_tracker[session_id]
                if entry.timestamp > cutoff_time
            ]
            if not self._session_tracker[session_id]:
                del self._session_tracker[session_id]
    
    def _analyze_command_patterns(self, command: str) -> Optional[Dict[str, Any]]:
        """Analyze command for threat patterns."""
        best_match = None
        highest_score = 0
        
        for pattern_name, pattern_info in self._command_patterns.items():
            for pattern in pattern_info['patterns']:
                if re.search(pattern, command, re.IGNORECASE):
                    score = self._get_severity_score(pattern_info['severity'])
                    if score > highest_score:
                        highest_score = score
                        best_match = {
                            'severity': pattern_info['severity'],
                            'category': pattern_info['category'],
                            'confidence': pattern_info['confidence'],
                            'indicators': [f"Command pattern: {pattern_name}"],
                            'severity_score': score
                        }
        
        return best_match
    
    def _analyze_event_type(self, entry: LogEntry) -> Optional[Dict[str, Any]]:
        """Analyze event type for threat indicators."""
        event_assessments = {
            'authentication': {
                'severity': 'low',
                'category': 'reconnaissance',
                'confidence': 0.6,
                'indicators': ['Authentication attempt']
            },
            'login': {
                'severity': 'medium',
                'category': 'reconnaissance',
                'confidence': 0.7,
                'indicators': ['Successful login']
            },
            'command': {
                'severity': 'low',
                'category': 'reconnaissance',
                'confidence': 0.5,
                'indicators': ['Command execution']
            },
            'file_access': {
                'severity': 'medium',
                'category': 'reconnaissance',
                'confidence': 0.6,
                'indicators': ['File system access']
            }
        }
        
        if entry.event_type in event_assessments:
            assessment = event_assessments[entry.event_type].copy()
            assessment['severity_score'] = self._get_severity_score(assessment['severity'])
            return assessment
        
        return None
    
    def _analyze_ip_behavior(self, entry: LogEntry) -> Optional[Dict[str, Any]]:
        """Analyze IP behavior patterns for threats."""
        ip_entries = self._ip_activity_tracker.get(entry.source_ip, [])
        
        if len(ip_entries) < 2:
            return None
        
        # Check for rapid activity (potential automated attacks)
        recent_entries = [
            e for e in ip_entries
            if (entry.timestamp - e.timestamp).total_seconds() <= 300  # 5 minutes
        ]
        
        if len(recent_entries) >= 10:
            return {
                'severity': 'high',
                'category': 'exploitation',
                'confidence': 0.8,
                'indicators': [f'Rapid activity: {len(recent_entries)} actions in 5 minutes'],
                'severity_score': 3
            }
        elif len(recent_entries) >= 5:
            return {
                'severity': 'medium',
                'category': 'reconnaissance',
                'confidence': 0.7,
                'indicators': [f'Moderate activity: {len(recent_entries)} actions in 5 minutes'],
                'severity_score': 2
            }
        
        return None
    
    def _get_severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score."""
        scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return scores.get(severity, 0)
    
    def detect_patterns(self, entries: List[LogEntry]) -> List[dict]:
        """
        Detect patterns across multiple log entries.
        
        Args:
            entries: List of LogEntry objects to analyze
            
        Returns:
            List of detected patterns
        """
        patterns = []
        
        if not entries:
            return patterns
        
        # Group entries by IP and session
        ip_groups = defaultdict(list)
        session_groups = defaultdict(list)
        
        for entry in entries:
            ip_groups[entry.source_ip].append(entry)
            session_groups[entry.session_id].append(entry)
        
        # Detect brute force patterns
        patterns.extend(self._detect_brute_force_patterns(ip_groups))
        
        # Detect command sequence patterns
        patterns.extend(self._detect_command_sequences(session_groups))
        
        # Detect time-based patterns
        patterns.extend(self._detect_time_patterns(entries))
        
        # Detect repeat offender patterns
        patterns.extend(self._detect_repeat_offenders(ip_groups))
        
        return patterns
    
    def _detect_brute_force_patterns(self, ip_groups: Dict[str, List[LogEntry]]) -> List[dict]:
        """Detect brute force attack patterns."""
        patterns = []
        
        for ip, entries in ip_groups.items():
            # Count authentication failures
            auth_failures = [
                e for e in entries
                if e.event_type == 'authentication' and 'failed' in e.message.lower()
            ]
            
            if len(auth_failures) >= 5:
                # Check if failures occurred within a short time window
                if auth_failures:
                    time_span = (auth_failures[-1].timestamp - auth_failures[0].timestamp).total_seconds()
                    if time_span <= 600:  # 10 minutes
                        patterns.append({
                            'type': 'brute_force_attack',
                            'source_ip': ip,
                            'severity': 'high',
                            'confidence': 0.9,
                            'description': f'Brute force attack detected: {len(auth_failures)} failed attempts in {time_span:.0f} seconds',
                            'indicators': [f'{len(auth_failures)} authentication failures', f'Time span: {time_span:.0f}s'],
                            'entry_count': len(auth_failures),
                            'time_span': time_span
                        })
        
        return patterns
    
    def _detect_command_sequences(self, session_groups: Dict[str, List[LogEntry]]) -> List[dict]:
        """Detect suspicious command sequences."""
        patterns = []
        
        for session_id, entries in session_groups.items():
            commands = [e.command for e in entries if e.command and e.event_type == 'command']
            
            if len(commands) < 3:
                continue
            
            # Look for reconnaissance sequences
            recon_commands = ['whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig']
            recon_count = sum(1 for cmd in commands if any(recon in cmd.lower() for recon in recon_commands))
            
            if recon_count >= 3:
                patterns.append({
                    'type': 'reconnaissance_sequence',
                    'session_id': session_id,
                    'source_ip': entries[0].source_ip,
                    'severity': 'medium',
                    'confidence': 0.8,
                    'description': f'Reconnaissance sequence detected: {recon_count} enumeration commands',
                    'indicators': [f'{recon_count} reconnaissance commands', 'Systematic enumeration'],
                    'command_count': len(commands),
                    'recon_count': recon_count
                })
            
            # Look for privilege escalation sequences
            priv_commands = ['sudo', 'su', 'passwd', 'chmod']
            priv_count = sum(1 for cmd in commands if any(priv in cmd.lower() for priv in priv_commands))
            
            if priv_count >= 2:
                patterns.append({
                    'type': 'privilege_escalation_sequence',
                    'session_id': session_id,
                    'source_ip': entries[0].source_ip,
                    'severity': 'high',
                    'confidence': 0.85,
                    'description': f'Privilege escalation sequence detected: {priv_count} escalation attempts',
                    'indicators': [f'{priv_count} privilege escalation commands', 'Potential compromise attempt'],
                    'command_count': len(commands),
                    'priv_count': priv_count
                })
        
        return patterns
    
    def _detect_time_patterns(self, entries: List[LogEntry]) -> List[dict]:
        """Detect time-based attack patterns."""
        patterns = []
        
        if len(entries) < 10:
            return patterns
        
        # Sort entries by timestamp
        sorted_entries = sorted(entries, key=lambda x: x.timestamp)
        
        # Detect burst activity
        time_windows = []
        window_size = timedelta(minutes=5)
        
        for i in range(len(sorted_entries)):
            window_start = sorted_entries[i].timestamp
            window_end = window_start + window_size
            
            window_entries = [
                e for e in sorted_entries[i:]
                if window_start <= e.timestamp <= window_end
            ]
            
            if len(window_entries) >= 20:
                time_windows.append({
                    'start': window_start,
                    'end': window_end,
                    'count': len(window_entries),
                    'entries': window_entries
                })
        
        # Report significant burst activity
        for window in time_windows:
            if window['count'] >= 20:
                patterns.append({
                    'type': 'burst_activity',
                    'severity': 'medium',
                    'confidence': 0.7,
                    'description': f'Burst activity detected: {window["count"]} events in 5 minutes',
                    'indicators': [f'{window["count"]} events in 5-minute window', 'Potential automated attack'],
                    'start_time': window['start'],
                    'end_time': window['end'],
                    'event_count': window['count']
                })
        
        return patterns
    
    def _detect_repeat_offenders(self, ip_groups: Dict[str, List[LogEntry]]) -> List[dict]:
        """Detect repeat offender IPs."""
        patterns = []
        
        for ip, entries in ip_groups.items():
            if len(entries) < 10:
                continue
            
            # Check activity span
            if entries:
                sorted_entries = sorted(entries, key=lambda x: x.timestamp)
                time_span = (sorted_entries[-1].timestamp - sorted_entries[0].timestamp).total_seconds()
                
                # If IP has been active for more than 1 hour with many events
                if time_span > 3600 and len(entries) >= 50:
                    patterns.append({
                        'type': 'repeat_offender',
                        'source_ip': ip,
                        'severity': 'medium',
                        'confidence': 0.8,
                        'description': f'Repeat offender detected: {len(entries)} events over {time_span/3600:.1f} hours',
                        'indicators': [f'{len(entries)} total events', f'Active for {time_span/3600:.1f} hours'],
                        'event_count': len(entries),
                        'time_span_hours': time_span / 3600
                    })
        
        return patterns
    
    def apply_custom_rules(self, entry: LogEntry) -> List[dict]:
        """
        Apply custom detection rules to a log entry.
        
        Args:
            entry: LogEntry to analyze
            
        Returns:
            List of alerts generated by custom rules
        """
        alerts = []
        
        # Load and apply custom rules
        alerts.extend(self._apply_command_rules(entry))
        alerts.extend(self._apply_file_access_rules(entry))
        alerts.extend(self._apply_ip_reputation_rules(entry))
        alerts.extend(self._apply_behavioral_rules(entry))
        
        return alerts
    
    def _apply_command_rules(self, entry: LogEntry) -> List[dict]:
        """Apply custom rules for command detection."""
        alerts = []
        
        if not entry.command:
            return alerts
        
        # Suspicious command patterns
        suspicious_commands = {
            'destructive_commands': {
                'patterns': [
                    r'rm\s+-rf\s+/',
                    r'dd\s+if=/dev/zero',
                    r'mkfs\.',
                    r'fdisk.*-d',
                    r'shred\s+',
                    r'wipefs\s+'
                ],
                'severity': 'critical',
                'confidence': 0.95,
                'description': 'Destructive command detected'
            },
            'fork_bombs': {
                'patterns': [
                    r':\(\)\{\s*:\|\:&\s*\};\:',
                    r'bomb\(\)\s*\{\s*bomb\|\s*bomb\s*&\s*\}',
                    r'while\s+true.*do.*done'
                ],
                'severity': 'critical',
                'confidence': 0.9,
                'description': 'Fork bomb or DoS attack detected'
            },
            'crypto_mining': {
                'patterns': [
                    r'\b(xmrig|cpuminer|cgminer|bfgminer)\b',
                    r'stratum\+tcp://',
                    r'--algo.*--pool',
                    r'minerd\s+'
                ],
                'severity': 'high',
                'confidence': 0.85,
                'description': 'Cryptocurrency mining activity detected'
            },
            'reverse_shells': {
                'patterns': [
                    r'nc.*-e\s+/bin/sh',
                    r'bash\s+-i\s+>&\s+/dev/tcp/',
                    r'python.*socket.*subprocess',
                    r'perl.*socket.*exec',
                    r'ruby.*socket.*exec'
                ],
                'severity': 'critical',
                'confidence': 0.9,
                'description': 'Reverse shell attempt detected'
            },
            'data_exfiltration': {
                'patterns': [
                    r'tar.*\|\s*(nc|netcat)',
                    r'(cat|dd).*\|\s*(nc|netcat)',
                    r'base64.*\|\s*(curl|wget)',
                    r'gzip.*\|\s*(curl|wget)'
                ],
                'severity': 'high',
                'confidence': 0.8,
                'description': 'Data exfiltration attempt detected'
            }
        }
        
        for rule_name, rule_info in suspicious_commands.items():
            for pattern in rule_info['patterns']:
                if re.search(pattern, entry.command, re.IGNORECASE):
                    alerts.append({
                        'rule_name': f'custom_command_{rule_name}',
                        'severity': rule_info['severity'],
                        'confidence': rule_info['confidence'],
                        'description': f"{rule_info['description']}: {entry.command}",
                        'indicators': [f'Command pattern: {rule_name}'],
                        'source_ip': entry.source_ip,
                        'session_id': entry.session_id,
                        'timestamp': entry.timestamp,
                        'matched_pattern': pattern
                    })
        
        return alerts
    
    def _apply_file_access_rules(self, entry: LogEntry) -> List[dict]:
        """Apply custom rules for file access detection."""
        alerts = []
        
        if not entry.file_path:
            return alerts
        
        # Sensitive file access rules
        sensitive_files = {
            'system_credentials': {
                'paths': ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow'],
                'severity': 'high',
                'confidence': 0.9,
                'description': 'Access to system credential files'
            },
            'ssh_keys': {
                'paths': ['/root/.ssh/', '/home/*/.ssh/', '/.ssh/authorized_keys', '/.ssh/id_rsa'],
                'severity': 'high',
                'confidence': 0.85,
                'description': 'Access to SSH key files'
            },
            'system_logs': {
                'paths': ['/var/log/auth.log', '/var/log/secure', '/var/log/messages', '/var/log/syslog'],
                'severity': 'medium',
                'confidence': 0.7,
                'description': 'Access to system log files'
            },
            'configuration_files': {
                'paths': ['/etc/sudoers', '/etc/hosts', '/etc/resolv.conf', '/etc/crontab'],
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'Access to system configuration files'
            },
            'database_files': {
                'paths': ['*.db', '*.sql', '*.mdb', '/var/lib/mysql/', '/var/lib/postgresql/'],
                'severity': 'high',
                'confidence': 0.8,
                'description': 'Access to database files'
            }
        }
        
        for rule_name, rule_info in sensitive_files.items():
            for path_pattern in rule_info['paths']:
                # Simple pattern matching - in production, use proper glob/regex
                if ('*' in path_pattern and path_pattern.replace('*', '') in entry.file_path) or \
                   (path_pattern in entry.file_path):
                    alerts.append({
                        'rule_name': f'custom_file_{rule_name}',
                        'severity': rule_info['severity'],
                        'confidence': rule_info['confidence'],
                        'description': f"{rule_info['description']}: {entry.file_path}",
                        'indicators': [f'File access: {rule_name}'],
                        'source_ip': entry.source_ip,
                        'session_id': entry.session_id,
                        'timestamp': entry.timestamp,
                        'file_path': entry.file_path
                    })
        
        return alerts
    
    def _apply_ip_reputation_rules(self, entry: LogEntry) -> List[dict]:
        """Apply IP reputation and geolocation rules."""
        alerts = []
        
        # IP-based rules
        ip_rules = {
            'tor_exit_nodes': {
                # In production, this would be loaded from threat feeds
                'ips': set(),  # Would contain known Tor exit node IPs
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'Connection from Tor exit node'
            },
            'known_malicious_ips': {
                # In production, loaded from threat intelligence feeds
                'ips': set(),  # Would contain known malicious IPs
                'severity': 'critical',
                'confidence': 0.95,
                'description': 'Connection from known malicious IP'
            },
            'suspicious_ranges': {
                # Example suspicious IP ranges
                'ranges': ['169.254.0.0/16', '127.0.0.0/8'],  # Link-local, localhost
                'severity': 'low',
                'confidence': 0.6,
                'description': 'Connection from suspicious IP range'
            }
        }
        
        # Check IP against reputation lists
        for rule_name, rule_info in ip_rules.items():
            if 'ips' in rule_info and entry.source_ip in rule_info['ips']:
                alerts.append({
                    'rule_name': f'custom_ip_{rule_name}',
                    'severity': rule_info['severity'],
                    'confidence': rule_info['confidence'],
                    'description': f"{rule_info['description']}: {entry.source_ip}",
                    'indicators': [f'IP reputation: {rule_name}'],
                    'source_ip': entry.source_ip,
                    'session_id': entry.session_id,
                    'timestamp': entry.timestamp
                })
        
        return alerts
    
    def _apply_behavioral_rules(self, entry: LogEntry) -> List[dict]:
        """Apply behavioral analysis rules."""
        alerts = []
        
        # Get recent activity for this IP
        ip_entries = self._ip_activity_tracker.get(entry.source_ip, [])
        session_entries = self._session_tracker.get(entry.session_id, [])
        
        # Behavioral patterns
        behavioral_rules = {
            'rapid_session_creation': {
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': 'medium',
                'confidence': 0.7,
                'description': 'Rapid session creation detected'
            },
            'command_diversity': {
                'threshold': 20,  # Many different commands
                'severity': 'medium',
                'confidence': 0.6,
                'description': 'High command diversity - possible automated scanning'
            },
            'failed_command_ratio': {
                'threshold': 0.8,  # 80% failed commands
                'min_commands': 10,
                'severity': 'medium',
                'confidence': 0.7,
                'description': 'High failed command ratio - possible brute force'
            }
        }
        
        # Check rapid session creation
        recent_sessions = set()
        cutoff_time = entry.timestamp - timedelta(seconds=300)
        for ip_entry in ip_entries:
            if ip_entry.timestamp > cutoff_time:
                recent_sessions.add(ip_entry.session_id)
        
        if len(recent_sessions) >= behavioral_rules['rapid_session_creation']['threshold']:
            alerts.append({
                'rule_name': 'custom_behavior_rapid_sessions',
                'severity': behavioral_rules['rapid_session_creation']['severity'],
                'confidence': behavioral_rules['rapid_session_creation']['confidence'],
                'description': f"{behavioral_rules['rapid_session_creation']['description']}: {len(recent_sessions)} sessions",
                'indicators': [f'Rapid sessions: {len(recent_sessions)}'],
                'source_ip': entry.source_ip,
                'session_id': entry.session_id,
                'timestamp': entry.timestamp,
                'session_count': len(recent_sessions)
            })
        
        # Check command diversity
        if len(session_entries) >= 10:
            unique_commands = set()
            for session_entry in session_entries:
                if session_entry.command:
                    unique_commands.add(session_entry.command.split()[0])  # First word of command
            
            if len(unique_commands) >= behavioral_rules['command_diversity']['threshold']:
                alerts.append({
                    'rule_name': 'custom_behavior_command_diversity',
                    'severity': behavioral_rules['command_diversity']['severity'],
                    'confidence': behavioral_rules['command_diversity']['confidence'],
                    'description': f"{behavioral_rules['command_diversity']['description']}: {len(unique_commands)} unique commands",
                    'indicators': [f'Command diversity: {len(unique_commands)}'],
                    'source_ip': entry.source_ip,
                    'session_id': entry.session_id,
                    'timestamp': entry.timestamp,
                    'unique_commands': len(unique_commands)
                })
        
        return alerts
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about current threat landscape."""
        stats = {
            'total_ips_tracked': len(self._ip_activity_tracker),
            'total_sessions_tracked': len(self._session_tracker),
            'threat_categories': defaultdict(int),
            'severity_distribution': defaultdict(int),
            'top_source_ips': [],
            'most_active_sessions': []
        }
        
        # Analyze all tracked entries
        all_entries = []
        for entries in self._ip_activity_tracker.values():
            all_entries.extend(entries)
        
        # Count threat categories and severities
        for entry in all_entries:
            assessment = self.analyze_entry(entry)
            stats['threat_categories'][assessment.category] += 1
            stats['severity_distribution'][assessment.severity] += 1
        
        # Get top source IPs by activity count
        ip_counts = [(ip, len(entries)) for ip, entries in self._ip_activity_tracker.items()]
        stats['top_source_ips'] = sorted(ip_counts, key=lambda x: x[1], reverse=True)[:10]
        
        # Get most active sessions
        session_counts = [(session, len(entries)) for session, entries in self._session_tracker.items()]
        stats['most_active_sessions'] = sorted(session_counts, key=lambda x: x[1], reverse=True)[:10]
        
        return dict(stats)
    
    def detect_suspicious_command_sequences(self, entries: List[LogEntry]) -> List[dict]:
        """
        Detect suspicious command sequences that indicate coordinated attacks.
        
        Args:
            entries: List of LogEntry objects to analyze
            
        Returns:
            List of detected suspicious sequences
        """
        sequences = []
        
        # Group entries by session
        session_groups = defaultdict(list)
        for entry in entries:
            if entry.command:
                session_groups[entry.session_id].append(entry)
        
        # Analyze each session for suspicious sequences
        for session_id, session_entries in session_groups.items():
            if len(session_entries) < 3:
                continue
            
            # Sort by timestamp
            session_entries.sort(key=lambda x: x.timestamp)
            commands = [entry.command for entry in session_entries]
            
            # Detect attack sequences
            sequences.extend(self._detect_attack_sequences(session_id, session_entries, commands))
        
        return sequences
    
    def _detect_attack_sequences(self, session_id: str, entries: List[LogEntry], commands: List[str]) -> List[dict]:
        """Detect specific attack sequences in command history."""
        sequences = []
        
        # Define attack sequence patterns
        attack_patterns = {
            'reconnaissance_to_exploitation': {
                'pattern': ['enumeration', 'vulnerability_scan', 'exploit'],
                'commands': {
                    'enumeration': ['whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig'],
                    'vulnerability_scan': ['find', 'locate', 'which', 'whereis'],
                    'exploit': ['sudo', 'su', 'chmod', 'wget', 'curl']
                },
                'severity': 'high',
                'confidence': 0.85
            },
            'persistence_establishment': {
                'pattern': ['access', 'modify', 'persist'],
                'commands': {
                    'access': ['cat', 'vi', 'nano', 'less'],
                    'modify': ['echo', 'sed', 'awk'],
                    'persist': ['crontab', 'systemctl', 'service', '.bashrc', '.profile']
                },
                'severity': 'critical',
                'confidence': 0.9
            },
            'data_collection': {
                'pattern': ['enumerate', 'collect', 'exfiltrate'],
                'commands': {
                    'enumerate': ['ls', 'find', 'locate'],
                    'collect': ['cat', 'cp', 'tar', 'zip'],
                    'exfiltrate': ['scp', 'rsync', 'nc', 'curl', 'wget']
                },
                'severity': 'high',
                'confidence': 0.8
            }
        }
        
        # Check for each attack pattern
        for pattern_name, pattern_info in attack_patterns.items():
            sequence_matches = self._match_command_sequence(commands, pattern_info)
            
            if sequence_matches['matched']:
                sequences.append({
                    'type': 'attack_sequence',
                    'pattern': pattern_name,
                    'session_id': session_id,
                    'source_ip': entries[0].source_ip,
                    'severity': pattern_info['severity'],
                    'confidence': pattern_info['confidence'],
                    'description': f'Attack sequence detected: {pattern_name}',
                    'indicators': sequence_matches['indicators'],
                    'command_count': len(commands),
                    'matched_commands': sequence_matches['matched_commands'],
                    'start_time': entries[0].timestamp,
                    'end_time': entries[-1].timestamp
                })
        
        return sequences
    
    def _match_command_sequence(self, commands: List[str], pattern_info: dict) -> dict:
        """Match commands against an attack sequence pattern."""
        pattern_stages = pattern_info['pattern']
        stage_commands = pattern_info['commands']
        
        matched_stages = []
        matched_commands = []
        indicators = []
        
        for stage in pattern_stages:
            stage_matched = False
            stage_command_list = stage_commands.get(stage, [])
            
            for command in commands:
                command_lower = command.lower()
                for stage_cmd in stage_command_list:
                    if stage_cmd in command_lower:
                        if stage not in matched_stages:
                            matched_stages.append(stage)
                            matched_commands.append(command)
                            indicators.append(f'{stage}: {command}')
                            stage_matched = True
                            break
                if stage_matched:
                    break
        
        # Consider sequence matched if at least 2 stages are present
        matched = len(matched_stages) >= 2
        
        return {
            'matched': matched,
            'matched_stages': matched_stages,
            'matched_commands': matched_commands,
            'indicators': indicators,
            'stage_count': len(matched_stages)
        }
    
    def track_repeat_offenders(self) -> List[dict]:
        """
        Track and identify repeat offender IPs based on activity patterns.
        
        Returns:
            List of repeat offender profiles
        """
        repeat_offenders = []
        
        for ip, entries in self._ip_activity_tracker.items():
            if len(entries) < 20:  # Minimum threshold for repeat offender
                continue
            
            # Analyze IP behavior
            profile = self._analyze_ip_profile(ip, entries)
            
            if profile['threat_score'] >= 0.7:  # High threat score threshold
                repeat_offenders.append(profile)
        
        # Sort by threat score
        repeat_offenders.sort(key=lambda x: x['threat_score'], reverse=True)
        
        return repeat_offenders
    
    def _analyze_ip_profile(self, ip: str, entries: List[LogEntry]) -> dict:
        """Analyze IP behavior to create threat profile."""
        if not entries:
            return {'ip': ip, 'threat_score': 0.0}
        
        # Sort entries by timestamp
        sorted_entries = sorted(entries, key=lambda x: x.timestamp)
        
        # Calculate metrics
        total_entries = len(entries)
        unique_sessions = len(set(entry.session_id for entry in entries))
        time_span = (sorted_entries[-1].timestamp - sorted_entries[0].timestamp).total_seconds()
        
        # Command analysis
        commands = [entry.command for entry in entries if entry.command]
        unique_commands = len(set(commands))
        
        # Event type analysis
        event_types = Counter(entry.event_type for entry in entries)
        
        # Calculate threat indicators
        threat_indicators = []
        threat_score = 0.0
        
        # High activity volume
        if total_entries > 100:
            threat_indicators.append('High activity volume')
            threat_score += 0.2
        
        # Many sessions
        if unique_sessions > 10:
            threat_indicators.append('Multiple sessions')
            threat_score += 0.15
        
        # Long duration activity
        if time_span > 3600:  # More than 1 hour
            threat_indicators.append('Persistent activity')
            threat_score += 0.1
        
        # High command diversity
        if unique_commands > 20:
            threat_indicators.append('High command diversity')
            threat_score += 0.15
        
        # Frequent authentication attempts
        auth_attempts = event_types.get('authentication', 0)
        if auth_attempts > 10:
            threat_indicators.append('Frequent authentication attempts')
            threat_score += 0.2
        
        # Rapid activity bursts
        if total_entries > 0 and time_span > 0:
            activity_rate = total_entries / (time_span / 60)  # Events per minute
            if activity_rate > 2:  # More than 2 events per minute on average
                threat_indicators.append('High activity rate')
                threat_score += 0.2
        
        return {
            'ip': ip,
            'threat_score': min(threat_score, 1.0),  # Cap at 1.0
            'total_entries': total_entries,
            'unique_sessions': unique_sessions,
            'unique_commands': unique_commands,
            'time_span_hours': time_span / 3600,
            'activity_rate': total_entries / (time_span / 60) if time_span > 0 else 0,
            'threat_indicators': threat_indicators,
            'event_type_distribution': dict(event_types),
            'first_seen': sorted_entries[0].timestamp,
            'last_seen': sorted_entries[-1].timestamp
        }
    
    def load_custom_rules_from_file(self, rules_file_path: str) -> bool:
        """
        Load custom detection rules from a configuration file.
        
        Args:
            rules_file_path: Path to the custom rules file
            
        Returns:
            True if rules loaded successfully, False otherwise
        """
        try:
            import yaml
            from pathlib import Path
            
            rules_path = Path(rules_file_path)
            if not rules_path.exists():
                return False
            
            with open(rules_path, 'r') as file:
                custom_rules = yaml.safe_load(file)
            
            # Merge custom rules with existing patterns
            if 'command_patterns' in custom_rules:
                self._command_patterns.update(custom_rules['command_patterns'])
            
            if 'threat_indicators' in custom_rules:
                self._threat_indicators.update(custom_rules['threat_indicators'])
            
            return True
            
        except Exception as e:
            # In production, log the error
            print(f"Error loading custom rules: {e}")
            return False
    
    def export_threat_rules(self, output_path: str) -> bool:
        """
        Export current threat detection rules to a file.
        
        Args:
            output_path: Path where to save the rules
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            import yaml
            from pathlib import Path
            
            rules_data = {
                'command_patterns': self._command_patterns,
                'threat_indicators': self._threat_indicators
            }
            
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as file:
                yaml.dump(rules_data, file, default_flow_style=False, indent=2)
            
            return True
            
        except Exception as e:
            # In production, log the error
            print(f"Error exporting rules: {e}")
            return False