# Frequently Asked Questions (FAQ)

This document answers common questions about the Honeypot Monitor CLI application.

## Table of Contents

1. [General Questions](#general-questions)
2. [Installation and Setup](#installation-and-setup)
3. [Configuration](#configuration)
4. [Usage and Features](#usage-and-features)
5. [Troubleshooting](#troubleshooting)
6. [Performance and Scalability](#performance-and-scalability)
7. [Security](#security)
8. [Integration](#integration)
9. [Development](#development)

## General Questions

### What is Honeypot Monitor CLI?

Honeypot Monitor CLI is a terminal-based application designed to monitor and analyze Kippo honeypot activity in real-time. It provides threat detection, IRC notifications, and an interactive terminal interface for security analysts.

### What honeypot systems does it support?

Currently, the application primarily supports Kippo honeypots. However, the architecture is designed to be extensible, and support for other honeypot systems (Cowrie, Dionaea, etc.) can be added through custom parsers.

### What are the main features?

- Real-time log monitoring and parsing
- Automated threat detection and categorization
- Interactive terminal user interface (TUI)
- IRC notifications for immediate alerts
- Historical data analysis and export
- Session correlation and tracking
- Customizable threat detection rules
- Performance monitoring and optimization

### Is it free and open source?

Yes, Honeypot Monitor CLI is released under the MIT License, making it free to use, modify, and distribute.

### What platforms are supported?

The application runs on Linux systems (Ubuntu, CentOS, Debian, etc.) with Python 3.8+. While it may work on macOS and Windows with appropriate dependencies, Linux is the primary supported platform.

## Installation and Setup

### What are the system requirements?

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, or similar)
- **Python**: Version 3.8 or higher
- **Memory**: 512MB RAM minimum (1GB recommended)
- **Disk Space**: 100MB for application, additional space for logs
- **Network**: Internet access for IRC notifications (optional)

### How do I install it?

The easiest method is using the interactive installer:

```bash
curl -sSL https://raw.githubusercontent.com/example/honeypot-monitor-cli/main/install.sh | bash
```

For manual installation, see the [User Guide](USER_GUIDE.md#installation-guide).

### Can I install it without root privileges?

Yes, the application can be installed in user space:

```bash
pip install --user -e .
```

The installer also supports user-only installation when run without sudo.

### Do I need to install additional dependencies?

The installer handles all Python dependencies automatically. However, you may need system packages for compilation:

```bash
# Ubuntu/Debian
sudo apt install python3-dev build-essential

# CentOS/RHEL
sudo yum install python3-devel gcc
```

### Can I run it in a Docker container?

Yes, Docker support is available. See the deployment documentation for container setup instructions.

## Configuration

### Where is the configuration file located?

The main configuration file is at:
- User installation: `~/.honeypot-monitor/config/config.yaml`
- System installation: `/etc/honeypot-monitor/config.yaml`

### How do I configure it for my Kippo installation?

The installer typically auto-detects Kippo installations. If manual configuration is needed:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"  # Update this path
  log_format: "kippo_default"
```

### Can I monitor multiple honeypots?

Yes, you can configure multiple honeypots in several ways:
1. Run separate instances with different configurations
2. Use the centralized monitoring feature (enterprise)
3. Configure log aggregation from multiple sources

### How do I set up IRC notifications?

Configure the IRC section in your config file:

```yaml
irc:
  enabled: true
  server: "irc.libera.chat"
  port: 6667
  channel: "#your-alerts"
  nickname: "honeypot-monitor"
  ssl: false
```

### Can I use environment variables for configuration?

Yes, many settings can be overridden with environment variables:

```bash
export HONEYPOT_LOG_PATH="/custom/path/kippo.log"
export HONEYPOT_IRC_SERVER="irc.example.com"
```

## Usage and Features

### How do I start the application?

After installation:

```bash
# Start with default configuration
honeypot-monitor

# Start with custom configuration
honeypot-monitor --config /path/to/config.yaml

# Start in background (daemon mode)
honeypot-monitor --daemon
```

### What keyboard shortcuts are available?

Common shortcuts in the TUI:
- `Tab` / `Shift+Tab`: Navigate between panels
- `q` / `Ctrl+C`: Quit application
- `h` / `F1`: Show help
- `r` / `F5`: Refresh current view
- `f`: Filter entries
- `s`: Search
- `e`: Export data

### How do I export data?

In the Log Viewer panel:
1. Press `e` to open export dialog
2. Choose format (CSV or JSON)
3. Select date range and filters
4. Specify output file location

### Can I create custom threat detection rules?

Yes, create custom rules in YAML format:

```yaml
# ~/.honeypot-monitor/rules/custom.yaml
rules:
  - name: "Cryptocurrency Mining"
    pattern: "(xmrig|cpuminer|minerd)"
    severity: "high"
    category: "exploitation"
```

### How does session correlation work?

The application automatically groups log entries by session ID and tracks:
- Command sequences within sessions
- Time-based activity patterns
- Cross-session correlation by IP address
- Session duration and behavior analysis

### What threat categories are detected?

Built-in categories include:
- **Reconnaissance**: Information gathering
- **Exploitation**: Vulnerability exploitation attempts
- **Persistence**: Maintaining access attempts
- **Data Exfiltration**: Data theft attempts

## Troubleshooting

### The application won't start. What should I check?

1. Verify Python version: `python3 --version`
2. Check configuration: `honeypot-monitor --test-config`
3. Verify log file access: `ls -la /opt/kippo/log/kippo.log`
4. Run in debug mode: `honeypot-monitor --debug`

### I'm not seeing any log entries. Why?

Common causes:
- Kippo is not running or not generating logs
- Incorrect log file path in configuration
- Permission issues accessing log files
- Log file rotation or movement

Check with: `tail -f /opt/kippo/log/kippo.log`

### IRC notifications aren't working. How do I fix this?

1. Test IRC connectivity: `telnet irc.server.com 6667`
2. Check firewall rules for IRC ports
3. Verify IRC configuration settings
4. Test with: `honeypot-monitor --test-irc`

### The interface looks garbled. What's wrong?

This usually indicates terminal compatibility issues:
- Ensure terminal supports colors: `tput colors`
- Try different terminal: `export TERM=xterm-256color`
- Disable colors: `honeypot-monitor --no-colors`

### How do I enable debug logging?

Add to configuration:

```yaml
logging:
  level: "DEBUG"
  console_output: true
```

Or run with: `honeypot-monitor --debug`

## Performance and Scalability

### How much memory does it use?

Memory usage depends on configuration:
- Minimal setup: ~50-100MB
- Default configuration: ~100-200MB
- High-volume environments: ~200-500MB

Control with:
```yaml
monitoring:
  max_entries_memory: 10000  # Adjust as needed
```

### Can it handle high-volume honeypots?

Yes, with proper configuration:
- Increase refresh intervals
- Enable batch processing
- Use multiple worker threads
- Implement log rotation

See [Configuration Examples](CONFIGURATION_EXAMPLES.md#high-volume-environments) for details.

### How do I optimize performance?

Performance tuning options:
```yaml
monitoring:
  refresh_interval: 2.0      # Slower refresh
  batch_processing: true     # Enable batching

interface:
  refresh_rate: 15           # Lower FPS
  enable_colors: false       # Disable colors

analysis:
  pattern_detection: false   # Disable if not needed
```

### Does it support clustering or load balancing?

Enterprise features include:
- Distributed processing across multiple nodes
- Load balancing for high-volume environments
- Centralized monitoring of multiple honeypots

### How do I monitor the monitor?

The application provides:
- Built-in performance metrics
- Health check endpoints (when API is enabled)
- Integration with monitoring systems (Prometheus, etc.)
- Systemd service status monitoring

## Security

### Is it secure to run on production systems?

Yes, with proper configuration:
- Run with minimal privileges
- Use read-only access to log files
- Secure IRC credentials
- Enable log encryption if needed
- Regular security updates

### How are IRC credentials protected?

- Store passwords in environment variables
- Use dedicated bot accounts with limited privileges
- Enable SSL/TLS for IRC connections
- Implement rate limiting to prevent abuse

### Can it detect advanced persistent threats (APTs)?

The application can detect many APT indicators:
- Suspicious command patterns
- Persistence mechanisms
- Data exfiltration attempts
- Custom rules for specific IOCs

However, it should be part of a broader security monitoring strategy.

### Does it log sensitive information?

The application logs:
- Honeypot activity (which is expected to be malicious)
- Application events and errors
- Performance metrics

Sensitive data handling:
- No real system credentials are logged
- IP addresses can be anonymized if needed
- Compliance features available for regulated environments

### How do I secure the configuration?

Best practices:
- Set proper file permissions: `chmod 600 config.yaml`
- Use environment variables for secrets
- Store configuration in secure locations
- Regular backup and version control

## Integration

### Can I integrate it with SIEM systems?

Yes, several integration options:
- Syslog export for real-time events
- JSON/CSV export for batch processing
- REST API for programmatic access
- Custom plugins for specific SIEM platforms

### Does it work with ELK Stack (Elasticsearch, Logstash, Kibana)?

Yes, you can:
- Export data to Elasticsearch directly
- Use Logstash to process exported logs
- Create Kibana dashboards for visualization
- Use Beats for log shipping

### Can I integrate it with Slack or other chat platforms?

Yes, through:
- Custom notifier plugins
- Webhook integrations
- IRC bridge services
- API-based integrations

### How do I integrate with existing monitoring systems?

Integration methods:
- Prometheus metrics export
- SNMP monitoring support
- Custom health check endpoints
- Log file monitoring by external systems

### Can I use it with configuration management tools?

Yes, it works with:
- Ansible playbooks for deployment
- Puppet/Chef for configuration management
- Docker/Kubernetes for containerized deployment
- Terraform for infrastructure as code

## Development

### How can I contribute to the project?

1. Fork the repository on GitHub
2. Create a feature branch
3. Make changes with appropriate tests
4. Submit a pull request

See the [Developer Guide](DEVELOPER_GUIDE.md) for detailed information.

### Can I create custom plugins?

Yes, the plugin architecture supports:
- Custom threat analyzers
- Custom log parsers
- Custom notification systems
- Custom TUI components

### How do I add support for other honeypot systems?

Implement the LogParserInterface for your honeypot:

```python
class CustomHoneypotParser(LogParserInterface):
    def parse_entry(self, line: str) -> Optional[LogEntry]:
        # Custom parsing logic
        pass
```

### Is there an API for programmatic access?

Yes, enable the REST API:

```bash
honeypot-monitor --enable-api --api-port 8080
```

API endpoints include:
- `/api/v1/status` - System status
- `/api/v1/threats` - Threat data
- `/api/v1/sessions` - Session information

### How do I report bugs or request features?

- **GitHub Issues**: For bugs and feature requests
- **Security Issues**: Email security@example.com
- **General Questions**: Community forums or IRC
- **Commercial Support**: Available for enterprise users

### Can I get commercial support?

Yes, commercial support options include:
- Professional support contracts
- Custom development services
- Training and consulting
- Enterprise deployment assistance

---

## Still Have Questions?

If your question isn't answered here:

1. **Check the documentation**: [User Guide](USER_GUIDE.md), [Troubleshooting](TROUBLESHOOTING.md)
2. **Search existing issues**: GitHub repository
3. **Ask the community**: IRC channel #honeypot-monitor on Libera.Chat
4. **Create an issue**: GitHub issues for bugs/features
5. **Contact support**: For commercial support inquiries

We're always happy to help improve the documentation based on user feedback!