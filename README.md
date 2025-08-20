# Honeypot Monitor CLI

A powerful terminal-based monitoring application for Kippo honeypot traffic analysis. This tool provides real-time monitoring, threat analysis, and IRC notifications through an intuitive terminal user interface (TUI) similar to lazydocker.

## Features

- **Real-time Monitoring**: Continuously monitor Kippo honeypot logs with live updates
- **Interactive TUI**: Rich terminal interface with keyboard navigation and color-coded displays
- **Threat Analysis**: Automatic categorization and severity scoring of suspicious activities
- **IRC Notifications**: Real-time alerts to IRC channels for immediate threat notification
- **Historical Analysis**: Search, filter, and export historical log data
- **Session Tracking**: Correlate activities across multiple sessions and track attacker behavior
- **Easy Installation**: Interactive setup script with automatic dependency management

## Quick Start

### Automatic Installation (Recommended)

1. Download and run the interactive installer:
```bash
curl -sSL https://raw.githubusercontent.com/example/honeypot-monitor-cli/main/install.sh | bash
```

Or clone the repository and run:
```bash
git clone https://github.com/example/honeypot-monitor-cli.git
cd honeypot-monitor-cli
./install.sh
```

The installer will:
- Check system requirements and dependencies
- Create a virtual environment
- Install Python packages
- Detect Kippo installations automatically
- Configure IRC notifications (optional)
- Create launcher scripts and systemd service (optional)

### Updating

To update an existing installation with the latest code changes:

```bash
# Clone or pull the latest changes
git clone <repository-url> honeypot-monitor-update
cd honeypot-monitor-update

# Run the update script
chmod +x update.sh
./update.sh
```

The update script will:
- Preserve your existing configuration
- Update the application code and dependencies
- Restart services if they were running
- Backup your config before making changes

### Manual Installation

If you prefer manual installation:

```bash
# Clone the repository
git clone https://github.com/example/honeypot-monitor-cli.git
cd honeypot-monitor-cli

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Starting the Application

After installation, start the monitor:

```bash
# If installed via installer script
honeypot-monitor

# Or with custom configuration
honeypot-monitor --config /path/to/config.yaml

# Override specific settings
honeypot-monitor --log-path /opt/kippo/log/kippo.log --daemon
```

### TUI Navigation

The terminal interface provides several panels:

- **Dashboard**: Real-time activity feed and connection statistics
- **Log Viewer**: Browse and search historical logs with filtering
- **Analysis Panel**: View threat assessments and pattern analysis
- **Settings**: Configure monitoring and IRC settings

#### Keyboard Shortcuts

- `Tab` / `Shift+Tab`: Navigate between panels
- `q` / `Ctrl+C`: Quit application
- `r`: Refresh current view
- `f`: Open filter dialog
- `s`: Open search
- `e`: Export current view
- `h`: Show help

### Configuration

The application uses YAML configuration files. The installer creates a default configuration, but you can customize it:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 10000

analysis:
  threat_threshold: "medium"
  custom_rules_path: "./rules/"

irc:
  enabled: true
  server: "irc.libera.chat"
  port: 6667
  channel: "#security-alerts"
  nickname: "honeypot-monitor"
  ssl: false
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"

interface:
  theme: "dark"
  key_bindings: "default"
```

### Running as a Service

The installer can optionally create a systemd service for background operation:

```bash
# Enable and start the service
systemctl --user enable honeypot-monitor.service
systemctl --user start honeypot-monitor.service

# Check status
systemctl --user status honeypot-monitor.service

# View logs
journalctl --user -u honeypot-monitor.service -f
```

## Requirements

### System Requirements

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, or similar)
- **Python**: 3.8 or higher
- **Memory**: 512MB RAM minimum, 1GB recommended
- **Disk Space**: 100MB for installation, additional space for log storage

### Dependencies

The application automatically installs these Python packages:

- `textual>=0.40.0` - Rich TUI framework
- `watchdog>=3.0.0` - File system monitoring
- `PyYAML>=6.0` - Configuration file parsing
- `irc>=20.0.0` - IRC client library
- `rich>=13.0.0` - Terminal formatting and colors

### Kippo Compatibility

Supports standard Kippo log formats. The installer automatically detects common Kippo installation paths:

- `/opt/kippo/log/kippo.log`
- `/var/log/kippo/kippo.log`
- `/usr/local/kippo/log/kippo.log`
- `$HOME/kippo/log/kippo.log`

## Project Structure

```
honeypot-monitor-cli/
├── install.sh                     # Interactive installation script
├── src/
│   └── honeypot_monitor/
│       ├── __init__.py
│       ├── main.py                 # Main application entry point
│       ├── interfaces/             # Abstract base classes and interfaces
│       ├── models/                 # Data models (LogEntry, Session, etc.)
│       ├── services/               # Business logic services
│       ├── tui/                    # Terminal UI components
│       └── config/                 # Configuration management
├── config/
│   └── default.yaml               # Default configuration template
├── systemd/
│   └── honeypot-monitor.service   # Systemd service template
├── tests/                         # Comprehensive test suite
├── requirements.txt               # Python dependencies
├── setup.py                      # Package installation script
└── README.md                     # This documentation
```

## Development

### Setting Up Development Environment

```bash
# Clone and setup
git clone https://github.com/example/honeypot-monitor-cli.git
cd honeypot-monitor-cli

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=honeypot_monitor

# Run specific test categories
pytest tests/test_services/
pytest tests/test_tui/
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[User Guide](docs/USER_GUIDE.md)**: Complete installation, configuration, and usage guide
- **[Configuration Examples](docs/CONFIGURATION_EXAMPLES.md)**: Sample configurations for different deployment scenarios
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)**: Common issues and solutions
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)**: Information for developers and contributors
- **[FAQ](docs/FAQ.md)**: Frequently asked questions

### Quick Help

- Built-in help: `honeypot-monitor --help`
- Test configuration: `honeypot-monitor --test-config`
- Debug mode: `honeypot-monitor --debug`
- System check: `honeypot-monitor --system-check`

### Getting Support

- **Documentation**: Check the comprehensive guides in `docs/`
- **GitHub Issues**: Report bugs and request features
- **Community**: IRC channel #honeypot-monitor on Libera.Chat
- **Commercial Support**: Available for enterprise deployments

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run tests and ensure code quality
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

This tool is designed for security monitoring. Please:
- Keep the application updated
- Secure IRC credentials and channels
- Monitor application logs for errors
- Follow security best practices for honeypot deployment

For security issues, please email security@example.com instead of using public issue tracker.