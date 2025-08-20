# Troubleshooting Guide

This guide helps diagnose and resolve common issues with the Honeypot Monitor CLI application.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Configuration Problems](#configuration-problems)
4. [Runtime Errors](#runtime-errors)
5. [Performance Issues](#performance-issues)
6. [IRC Connection Problems](#irc-connection-problems)
7. [Log Parsing Issues](#log-parsing-issues)
8. [Interface Problems](#interface-problems)
9. [System Integration Issues](#system-integration-issues)
10. [Advanced Debugging](#advanced-debugging)

## Quick Diagnostics

### Health Check Commands

Run these commands to quickly identify issues:

```bash
# Check application version and basic info
honeypot-monitor --version

# Test configuration file
honeypot-monitor --test-config

# Check system requirements
honeypot-monitor --system-check

# Test log file access
honeypot-monitor --test-log-access

# Test IRC connectivity
honeypot-monitor --test-irc

# Run in debug mode
honeypot-monitor --debug --verbose
```

### Log File Locations

Check these locations for diagnostic information:

```bash
# Application logs
tail -f ~/.honeypot-monitor/logs/app.log

# System service logs (if running as service)
journalctl -u honeypot-monitor.service -f

# Installation logs
cat ~/.honeypot-monitor/logs/install.log

# Error logs
grep ERROR ~/.honeypot-monitor/logs/app.log
```

### Common Status Indicators

Look for these indicators in the interface:

- **Green dot**: Service running normally
- **Yellow dot**: Warning condition
- **Red dot**: Error or disconnected
- **Gray dot**: Service disabled

## Installation Issues

### Python Version Problems

**Problem**: "Python version 3.8+ required"

**Solution**:
```bash
# Check current Python version
python3 --version

# Install newer Python (Ubuntu/Debian)
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-pip

# Install newer Python (CentOS/RHEL)
sudo yum install python39 python39-pip

# Use specific Python version
python3.9 -m venv venv
source venv/bin/activate
```

### Permission Errors

**Problem**: "Permission denied" during installation

**Solutions**:
```bash
# Option 1: User installation
pip install --user -e .

# Option 2: Fix ownership
sudo chown -R $USER:$USER ~/.honeypot-monitor

# Option 3: Use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Missing System Dependencies

**Problem**: "Failed building wheel" or compilation errors

**Solutions**:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3-dev build-essential libffi-dev libssl-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel libffi-devel openssl-devel

# Alpine Linux
sudo apk add python3-dev gcc musl-dev libffi-dev openssl-dev
```

### Network Issues During Installation

**Problem**: "Could not fetch URL" or timeout errors

**Solutions**:
```bash
# Use different PyPI mirror
pip install -i https://pypi.org/simple/ -e .

# Configure proxy (if behind corporate firewall)
pip install --proxy http://proxy.company.com:8080 -e .

# Offline installation
pip download -r requirements.txt
pip install --no-index --find-links . -e .
```

### Virtual Environment Issues

**Problem**: Virtual environment activation fails

**Solutions**:
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate

# Check venv module availability
python3 -m venv --help

# Alternative: use virtualenv
pip install virtualenv
virtualenv venv
source venv/bin/activate
```

## Configuration Problems

### Configuration File Not Found

**Problem**: "Configuration file not found"

**Solutions**:
```bash
# Create default configuration
honeypot-monitor --create-config

# Specify configuration file location
honeypot-monitor --config /path/to/config.yaml

# Check expected locations
ls -la ~/.honeypot-monitor/config/config.yaml
ls -la /etc/honeypot-monitor/config.yaml
```

### YAML Syntax Errors

**Problem**: "YAML parsing error" or "Invalid configuration"

**Solutions**:
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check indentation (use spaces, not tabs)
cat -A config.yaml | grep -E '^\t'

# Validate configuration
honeypot-monitor --test-config --verbose
```

### Invalid Configuration Values

**Problem**: "Invalid configuration value" errors

**Common fixes**:
```yaml
# Fix boolean values (use lowercase)
irc:
  enabled: true  # not True or TRUE

# Fix numeric values (no quotes)
monitoring:
  refresh_interval: 1.0  # not "1.0"

# Fix list syntax
alert_types:
  - "new_host"     # correct
  - "high_threat"  # correct
# not: alert_types: ["new_host", "high_threat"]
```

### Environment Variable Issues

**Problem**: Environment variables not recognized

**Solutions**:
```bash
# Check environment variables
env | grep HONEYPOT

# Export variables properly
export HONEYPOT_LOG_PATH="/opt/kippo/log/kippo.log"

# Use in configuration file
honeypot:
  log_path: "${HONEYPOT_LOG_PATH}"

# Debug variable expansion
honeypot-monitor --debug --show-config
```

## Runtime Errors

### Application Crashes on Startup

**Problem**: Application exits immediately after starting

**Diagnostic steps**:
```bash
# Run with debug output
honeypot-monitor --debug --verbose

# Check for Python import errors
python3 -c "import honeypot_monitor"

# Verify all dependencies
pip check

# Check system resources
free -h
df -h
```

### Memory Errors

**Problem**: "MemoryError" or "Out of memory"

**Solutions**:
```yaml
# Reduce memory usage in configuration
monitoring:
  max_entries_memory: 5000  # Reduce from default

interface:
  log_buffer_size: 500      # Reduce buffer size

# Enable memory management
performance:
  memory_limit: "1GB"
  gc_threshold: 5000
```

### File Access Errors

**Problem**: "Permission denied" accessing log files

**Solutions**:
```bash
# Check file permissions
ls -la /opt/kippo/log/kippo.log

# Add user to appropriate group
sudo usermod -a -G kippo $USER

# Use sudo for testing
sudo honeypot-monitor --test-log-access

# Change file permissions (if safe)
sudo chmod 644 /opt/kippo/log/kippo.log
```

### Process Hanging

**Problem**: Application becomes unresponsive

**Diagnostic steps**:
```bash
# Check process status
ps aux | grep honeypot-monitor

# Check system resources
top -p $(pgrep honeypot-monitor)

# Send debug signal (if supported)
kill -USR1 $(pgrep honeypot-monitor)

# Force termination
kill -TERM $(pgrep honeypot-monitor)
```

## Performance Issues

### High CPU Usage

**Problem**: Application consuming excessive CPU

**Solutions**:
```yaml
# Reduce refresh frequency
monitoring:
  refresh_interval: 2.0     # Increase from 1.0

interface:
  refresh_rate: 15          # Reduce from 30

# Disable expensive features
analysis:
  pattern_detection: false
  behavioral_analysis: false
```

### High Memory Usage

**Problem**: Application consuming too much memory

**Solutions**:
```yaml
# Limit memory usage
monitoring:
  max_entries_memory: 5000  # Reduce significantly

interface:
  log_buffer_size: 500      # Reduce buffer

# Enable garbage collection
performance:
  gc_threshold: 1000
  memory_cleanup_interval: 300
```

### Slow Response Times

**Problem**: Interface feels sluggish or unresponsive

**Solutions**:
```yaml
# Optimize interface settings
interface:
  refresh_rate: 20          # Reduce refresh rate
  enable_colors: false      # Disable colors for speed
  
# Reduce processing load
monitoring:
  batch_processing: true
  batch_size: 50

# Use threading
analysis:
  analysis_threads: 2
```

### Disk I/O Issues

**Problem**: High disk usage or slow file operations

**Solutions**:
```bash
# Check disk usage
iostat -x 1

# Monitor file operations
lsof -p $(pgrep honeypot-monitor)

# Optimize log rotation
logrotate /etc/logrotate.d/honeypot-monitor
```

## IRC Connection Problems

### Connection Refused

**Problem**: "Connection refused" to IRC server

**Solutions**:
```bash
# Test connectivity manually
telnet irc.libera.chat 6667

# Check firewall rules
sudo iptables -L | grep 6667

# Try different port
irc:
  port: 6697  # Try SSL port
  ssl: true

# Check DNS resolution
nslookup irc.libera.chat
```

### Authentication Failures

**Problem**: "Authentication failed" or "Nickname in use"

**Solutions**:
```yaml
# Use different nickname
irc:
  nickname: "honeypot-monitor-2"

# Add password if required
irc:
  password: "your_password"

# Use NickServ authentication
irc:
  nickserv_password: "your_nickserv_password"
```

### SSL/TLS Issues

**Problem**: SSL connection failures

**Solutions**:
```yaml
# Disable SSL certificate verification (testing only)
irc:
  ssl: true
  ssl_verify: false

# Specify certificate bundle
irc:
  ssl_cert_file: "/etc/ssl/certs/ca-certificates.crt"

# Use non-SSL connection
irc:
  port: 6667
  ssl: false
```

### Message Delivery Problems

**Problem**: Messages not appearing in IRC channel

**Solutions**:
```bash
# Check bot is in channel
/whois honeypot-monitor

# Verify channel permissions
/mode #channel

# Test message sending
honeypot-monitor --test-irc --send-test-message

# Check rate limiting
irc:
  rate_limit: 10  # Increase limit
```

## Log Parsing Issues

### Log Format Not Recognized

**Problem**: "Unknown log format" or parsing failures

**Solutions**:
```yaml
# Specify log format explicitly
honeypot:
  log_format: "kippo_default"

# Use custom format
honeypot:
  log_format: "custom"
  custom_format:
    timestamp_pattern: "%Y-%m-%d %H:%M:%S%z"
    entry_pattern: "\\[(.*?)\\] (.*)"
```

### Encoding Issues

**Problem**: "UnicodeDecodeError" or garbled text

**Solutions**:
```yaml
# Specify file encoding
honeypot:
  log_encoding: "utf-8"

# Try different encodings
honeypot:
  log_encoding: "latin1"  # or "cp1252"
```

### Large Log Files

**Problem**: Slow parsing of large log files

**Solutions**:
```yaml
# Enable batch processing
monitoring:
  batch_processing: true
  batch_size: 100

# Limit initial parsing
monitoring:
  initial_parse_limit: 10000

# Use log rotation
logrotate:
  enabled: true
  max_size: "100MB"
```

### Missing Log Entries

**Problem**: Some log entries not appearing

**Solutions**:
```bash
# Check file permissions
ls -la /opt/kippo/log/kippo.log

# Verify file is being written
tail -f /opt/kippo/log/kippo.log

# Check for file rotation
ls -la /opt/kippo/log/kippo.log*

# Test parsing manually
honeypot-monitor --test-parser --file /opt/kippo/log/kippo.log
```

## Interface Problems

### Display Issues

**Problem**: Garbled display or layout problems

**Solutions**:
```bash
# Check terminal capabilities
echo $TERM
tput colors

# Set terminal type
export TERM=xterm-256color

# Disable colors
honeypot-monitor --no-colors

# Try different terminal
# Use tmux, screen, or different terminal emulator
```

### Keyboard Input Problems

**Problem**: Keys not working or wrong actions

**Solutions**:
```yaml
# Change key bindings
interface:
  key_bindings: "vim"  # or "emacs"

# Reset to defaults
interface:
  key_bindings: "default"

# Check terminal settings
stty -a
```

### Font and Character Issues

**Problem**: Missing characters or font problems

**Solutions**:
```bash
# Install Unicode fonts
sudo apt install fonts-dejavu-core

# Check locale settings
locale

# Set UTF-8 locale
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
```

### Screen Size Issues

**Problem**: Interface doesn't fit screen

**Solutions**:
```bash
# Check terminal size
tput lines
tput cols

# Resize terminal (minimum 80x24)
resize

# Use scrollable interface
interface:
  scrollable: true
```

## System Integration Issues

### Systemd Service Problems

**Problem**: Service fails to start or stops unexpectedly

**Solutions**:
```bash
# Check service status
systemctl --user status honeypot-monitor.service

# View service logs
journalctl --user -u honeypot-monitor.service -f

# Reload service configuration
systemctl --user daemon-reload
systemctl --user restart honeypot-monitor.service

# Check service file
cat ~/.config/systemd/user/honeypot-monitor.service
```

### Cron Job Issues

**Problem**: Scheduled tasks not running

**Solutions**:
```bash
# Check cron logs
grep honeypot /var/log/cron

# Test cron command manually
/usr/local/bin/honeypot-monitor --report daily

# Check cron environment
env - /bin/bash -c 'your_command'

# Add to crontab with full paths
0 6 * * * /usr/local/bin/honeypot-monitor --report daily
```

### Docker Container Issues

**Problem**: Container startup or runtime problems

**Solutions**:
```bash
# Check container logs
docker logs honeypot-monitor

# Run interactively for debugging
docker run -it honeypot-monitor /bin/bash

# Check volume mounts
docker inspect honeypot-monitor

# Verify environment variables
docker exec honeypot-monitor env
```

## Advanced Debugging

### Enable Debug Logging

```yaml
# Maximum debug output
logging:
  level: "DEBUG"
  console_output: true
  debug_modules:
    - "log_parser"
    - "threat_analyzer"
    - "irc_notifier"
```

### Performance Profiling

```bash
# Run with profiling
honeypot-monitor --profile --profile-output /tmp/profile.stats

# Analyze profile
python3 -c "
import pstats
p = pstats.Stats('/tmp/profile.stats')
p.sort_stats('cumulative').print_stats(20)
"
```

### Memory Debugging

```bash
# Install memory profiler
pip install memory-profiler

# Run with memory profiling
mprof run honeypot-monitor
mprof plot
```

### Network Debugging

```bash
# Monitor network connections
netstat -tulpn | grep honeypot-monitor

# Capture network traffic
sudo tcpdump -i any -w /tmp/honeypot-traffic.pcap port 6667

# Analyze with Wireshark
wireshark /tmp/honeypot-traffic.pcap
```

### Strace Debugging

```bash
# Trace system calls
strace -f -o /tmp/honeypot.strace honeypot-monitor

# Analyze file operations
grep openat /tmp/honeypot.strace

# Check for errors
grep -E "(ENOENT|EACCES|EPERM)" /tmp/honeypot.strace
```

### Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited

# Analyze core dump (if application crashes)
gdb python3 core
(gdb) bt
(gdb) info registers
```

## Getting Help

### Before Reporting Issues

1. **Check this troubleshooting guide**
2. **Search existing issues** on GitHub
3. **Enable debug logging** and capture logs
4. **Create minimal reproduction** case
5. **Gather system information**:
   ```bash
   honeypot-monitor --system-info > system-info.txt
   ```

### Information to Include in Bug Reports

- **Version information**: `honeypot-monitor --version`
- **System information**: OS, Python version, architecture
- **Configuration file**: Sanitized configuration
- **Error logs**: Relevant log entries
- **Steps to reproduce**: Minimal reproduction steps
- **Expected vs actual behavior**

### Community Resources

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check docs/ directory
- **IRC Channel**: #honeypot-monitor on Libera.Chat
- **Mailing List**: honeypot-monitor@lists.example.com

### Professional Support

For enterprise deployments requiring professional support:

- **Commercial Support**: Available through support contracts
- **Consulting Services**: Custom deployment and integration
- **Training**: On-site or remote training sessions
- **Custom Development**: Feature development and customization

This troubleshooting guide covers the most common issues and their solutions. For issues not covered here, please consult the community resources or professional support options.