# Developer Guide

This guide provides comprehensive information for developers who want to contribute to, extend, or integrate with the Honeypot Monitor CLI application.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Architecture Overview](#architecture-overview)
3. [Code Structure](#code-structure)
4. [Core Components](#core-components)
5. [Extending the Application](#extending-the-application)
6. [Plugin Development](#plugin-development)
7. [Testing](#testing)
8. [Code Quality](#code-quality)
9. [Contributing](#contributing)
10. [API Reference](#api-reference)

## Development Environment Setup

### Prerequisites

- **Python 3.8+**: Required for modern async/await syntax and type hints
- **Git**: For version control
- **Make**: For build automation (optional)
- **Docker**: For containerized development (optional)

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/example/honeypot-monitor-cli.git
cd honeypot-monitor-cli

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install the package in development mode
pip install -e .

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies

```txt
# requirements-dev.txt
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-asyncio>=0.21.0
black>=22.0.0
flake8>=5.0.0
mypy>=1.0.0
isort>=5.10.0
pre-commit>=2.20.0
sphinx>=5.0.0
sphinx-rtd-theme>=1.0.0
```

### IDE Configuration

#### VS Code

```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

#### PyCharm

- Set interpreter to `./venv/bin/python`
- Enable Black formatter
- Configure flake8 and mypy inspections
- Set import optimization to use isort

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=honeypot_monitor --cov-report=html

# Run specific test categories
pytest tests/test_services/
pytest tests/test_models/
pytest tests/test_tui/

# Run integration tests
pytest tests/test_integration/

# Run performance tests
pytest tests/test_performance/ -v -s
```

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   TUI Components │  │   CLI Interface │  │  API Server │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Application Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Event Manager   │  │ Service Coord.  │  │ Config Mgr  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                     Service Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  Log Monitor    │  │ Threat Analyzer │  │ IRC Notifier│ │
│  │  Log Parser     │  │ Alert Manager   │  │ Performance │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                      Data Layer                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Data Models   │  │   Interfaces    │  │   Storage   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Design Patterns

The application uses several design patterns:

- **Observer Pattern**: Event-driven architecture with EventManager
- **Strategy Pattern**: Pluggable analyzers and parsers
- **Factory Pattern**: Component creation and configuration
- **Singleton Pattern**: Configuration and resource managers
- **Command Pattern**: TUI actions and CLI commands

### Key Principles

- **Separation of Concerns**: Clear layer boundaries
- **Dependency Injection**: Loose coupling between components
- **Event-Driven Architecture**: Asynchronous communication
- **Plugin Architecture**: Extensible functionality
- **Type Safety**: Comprehensive type hints

## Code Structure

### Directory Layout

```
src/honeypot_monitor/
├── __init__.py                 # Package initialization
├── main.py                     # Application entry point
├── interfaces/                 # Abstract base classes
│   ├── __init__.py
│   ├── analyzer_interface.py   # Threat analyzer interface
│   ├── log_parser_interface.py # Log parser interface
│   ├── monitor_interface.py    # Monitor interface
│   └── notifier_interface.py   # Notifier interface
├── models/                     # Data models
│   ├── __init__.py
│   ├── log_entry.py           # Log entry model
│   ├── session.py             # Session model
│   ├── threat_assessment.py   # Threat assessment model
│   ├── irc_alert.py          # IRC alert model
│   └── converters.py         # Model converters
├── services/                   # Business logic services
│   ├── __init__.py
│   ├── log_monitor.py         # File monitoring service
│   ├── log_parser.py          # Log parsing service
│   ├── threat_analyzer.py     # Threat analysis service
│   ├── irc_notifier.py        # IRC notification service
│   ├── alert_manager.py       # Alert management service
│   ├── event_manager.py       # Event coordination service
│   ├── service_coordinator.py # Service orchestration
│   ├── memory_manager.py      # Memory management
│   └── performance_monitor.py # Performance monitoring
├── tui/                       # Terminal UI components
│   ├── __init__.py
│   ├── main_app.py           # Main TUI application
│   ├── dashboard.py          # Dashboard panel
│   ├── log_viewer.py         # Log viewer panel
│   ├── analysis_panel.py     # Analysis panel
│   ├── settings_panel.py     # Settings panel
│   └── *.tcss                # Textual CSS files
├── config/                    # Configuration management
│   ├── __init__.py
│   ├── config_manager.py     # Configuration loader
│   └── settings.py           # Settings models
└── utils/                     # Utility functions
    ├── __init__.py
    ├── logging.py            # Logging utilities
    ├── validation.py         # Validation helpers
    └── formatters.py         # Data formatters
```

### Import Structure

```python
# Standard library imports
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

# Third-party imports
import yaml
from textual.app import App
from watchdog.observers import Observer

# Local imports
from honeypot_monitor.interfaces.analyzer_interface import AnalyzerInterface
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.services.event_manager import EventManager
```

## Core Components

### Event Manager

The EventManager is the central communication hub:

```python
from honeypot_monitor.services.event_manager import EventManager, EventType

# Create event manager
event_manager = EventManager(worker_threads=4)

# Subscribe to events
def handle_log_entry(event):
    log_entry = event.data
    print(f"New log entry: {log_entry.message}")

event_manager.subscribe(EventType.LOG_ENTRY, handle_log_entry)

# Publish events
event_manager.publish_log_entry(log_entry)
```

### Log Parser

Extensible log parsing system:

```python
from honeypot_monitor.services.log_parser import KippoLogParser

parser = KippoLogParser()
entry = parser.parse_entry(log_line)

if entry:
    print(f"Parsed: {entry.timestamp} - {entry.message}")
```

### Threat Analyzer

Pluggable threat analysis:

```python
from honeypot_monitor.services.threat_analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer()
threat = analyzer.analyze_entry(log_entry)

if threat and threat.severity == "high":
    print(f"High threat detected: {threat.category}")
```

### Configuration System

Type-safe configuration management:

```python
from honeypot_monitor.config.config_manager import ConfigManager

config_manager = ConfigManager()
config = config_manager.load_config("config.yaml")

# Access configuration
log_path = config.honeypot.log_path
irc_enabled = config.irc.enabled
```

## Extending the Application

### Creating Custom Analyzers

Implement the AnalyzerInterface:

```python
from honeypot_monitor.interfaces.analyzer_interface import AnalyzerInterface
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.models.threat_assessment import ThreatAssessment

class CustomAnalyzer(AnalyzerInterface):
    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAssessment]:
        """Analyze a log entry for threats."""
        if self._is_suspicious(entry):
            return ThreatAssessment(
                severity="medium",
                category="custom_threat",
                confidence=0.8,
                indicators=[f"Custom pattern in: {entry.command}"],
                recommended_action="investigate"
            )
        return None
    
    def _is_suspicious(self, entry: LogEntry) -> bool:
        """Custom threat detection logic."""
        if entry.command and "suspicious_pattern" in entry.command:
            return True
        return False
```

### Creating Custom Parsers

Implement the LogParserInterface:

```python
from honeypot_monitor.interfaces.log_parser_interface import LogParserInterface
from honeypot_monitor.models.log_entry import LogEntry
import re
from datetime import datetime

class CustomLogParser(LogParserInterface):
    def __init__(self):
        self.pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\+\d{4} '
            r'\[.*?,(\d+),([0-9.]+)\] (.+)'
        )
    
    def parse_entry(self, line: str) -> Optional[LogEntry]:
        """Parse a custom log format."""
        match = self.pattern.match(line)
        if not match:
            return None
        
        timestamp_str, session_id, source_ip, message = match.groups()
        
        return LogEntry(
            timestamp=datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"),
            session_id=session_id,
            event_type=self._extract_event_type(message),
            source_ip=source_ip,
            message=message,
            command=self._extract_command(message)
        )
    
    def _extract_event_type(self, message: str) -> str:
        """Extract event type from message."""
        if "CMD:" in message:
            return "command"
        elif "login attempt" in message:
            return "login"
        return "unknown"
    
    def _extract_command(self, message: str) -> Optional[str]:
        """Extract command from message."""
        if "CMD:" in message:
            return message.split("CMD:", 1)[1].strip()
        return None
```

### Creating Custom Notifiers

Implement the NotifierInterface:

```python
from honeypot_monitor.interfaces.notifier_interface import NotifierInterface
from honeypot_monitor.models.threat_assessment import ThreatAssessment
import requests

class SlackNotifier(NotifierInterface):
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(self, alert_type: str, message: str) -> bool:
        """Send alert to Slack."""
        payload = {
            "text": f"[{alert_type.upper()}] {message}",
            "username": "Honeypot Monitor",
            "icon_emoji": ":warning:"
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
            return False
    
    def send_threat_alert(self, threat: ThreatAssessment, source_ip: str) -> bool:
        """Send threat-specific alert."""
        message = f"Threat detected from {source_ip}: {threat.category} ({threat.severity})"
        return self.send_alert("THREAT", message)
```

### Adding TUI Components

Create custom TUI panels:

```python
from textual.containers import Container
from textual.widgets import Static, DataTable
from honeypot_monitor.tui.base_panel import BasePanel

class CustomPanel(BasePanel):
    """Custom analysis panel."""
    
    def compose(self):
        """Compose the panel layout."""
        yield Container(
            Static("Custom Analysis", classes="panel-title"),
            DataTable(id="custom-table"),
            classes="panel"
        )
    
    def on_mount(self):
        """Initialize the panel."""
        table = self.query_one("#custom-table", DataTable)
        table.add_columns("Metric", "Value")
        self.update_data()
    
    def update_data(self):
        """Update panel data."""
        table = self.query_one("#custom-table", DataTable)
        table.clear()
        
        # Add custom metrics
        metrics = self.get_custom_metrics()
        for metric, value in metrics.items():
            table.add_row(metric, str(value))
    
    def get_custom_metrics(self) -> dict:
        """Get custom metrics to display."""
        return {
            "Custom Metric 1": 42,
            "Custom Metric 2": "Active",
            "Custom Metric 3": "2024-01-15"
        }
```

## Plugin Development

### Plugin Architecture

The application supports plugins through a discovery mechanism:

```python
# plugins/example_plugin.py
from honeypot_monitor.interfaces.plugin_interface import PluginInterface

class ExamplePlugin(PluginInterface):
    name = "example_plugin"
    version = "1.0.0"
    description = "Example plugin for demonstration"
    
    def initialize(self, app_context):
        """Initialize the plugin."""
        self.app_context = app_context
        self.register_handlers()
    
    def register_handlers(self):
        """Register event handlers."""
        event_manager = self.app_context.event_manager
        event_manager.subscribe("log_entry", self.handle_log_entry)
    
    def handle_log_entry(self, event):
        """Handle log entry events."""
        log_entry = event.data
        # Custom processing logic
        pass
    
    def shutdown(self):
        """Clean up plugin resources."""
        pass
```

### Plugin Configuration

```yaml
# config.yaml
plugins:
  enabled: true
  search_paths:
    - "~/.honeypot-monitor/plugins"
    - "/usr/local/share/honeypot-monitor/plugins"
  
  example_plugin:
    enabled: true
    config:
      custom_setting: "value"
```

### Plugin Loading

```python
from honeypot_monitor.core.plugin_manager import PluginManager

plugin_manager = PluginManager()
plugin_manager.load_plugins()

# Get loaded plugins
plugins = plugin_manager.get_loaded_plugins()
```

## Testing

### Test Structure

```
tests/
├── __init__.py
├── conftest.py                 # Pytest configuration
├── test_models/               # Model tests
│   ├── test_log_entry.py
│   ├── test_session.py
│   └── test_threat_assessment.py
├── test_services/             # Service tests
│   ├── test_log_parser.py
│   ├── test_threat_analyzer.py
│   └── test_irc_notifier.py
├── test_tui/                  # TUI tests
│   ├── test_main_app.py
│   └── test_dashboard.py
├── test_integration/          # Integration tests
│   ├── test_end_to_end.py
│   └── test_performance.py
└── fixtures/                  # Test data
    ├── sample_logs.txt
    └── test_config.yaml
```

### Writing Unit Tests

```python
import pytest
from unittest.mock import Mock, patch
from honeypot_monitor.services.log_parser import KippoLogParser
from honeypot_monitor.models.log_entry import LogEntry

class TestKippoLogParser:
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = KippoLogParser()
    
    def test_parse_valid_entry(self):
        """Test parsing a valid log entry."""
        log_line = "2024-01-15 10:30:15+0000 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,1,192.168.1.100] CMD: ls -la"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry is not None
        assert entry.source_ip == "192.168.1.100"
        assert entry.command == "ls -la"
        assert entry.event_type == "command"
    
    def test_parse_invalid_entry(self):
        """Test parsing an invalid log entry."""
        log_line = "Invalid log entry format"
        
        entry = self.parser.parse_entry(log_line)
        
        assert entry is None
    
    @pytest.mark.parametrize("log_line,expected_ip", [
        ("...192.168.1.100] CMD: test", "192.168.1.100"),
        ("...10.0.0.1] login attempt", "10.0.0.1"),
        ("...172.16.0.50] connection lost", "172.16.0.50"),
    ])
    def test_ip_extraction(self, log_line, expected_ip):
        """Test IP address extraction."""
        # Implementation depends on actual parser logic
        pass
```

### Integration Testing

```python
import pytest
import tempfile
import os
from honeypot_monitor.services.log_monitor import LogMonitor
from honeypot_monitor.services.event_manager import EventManager

class TestLogMonitorIntegration:
    @pytest.fixture
    def temp_log_file(self):
        """Create temporary log file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            yield f.name
        os.unlink(f.name)
    
    def test_real_time_monitoring(self, temp_log_file):
        """Test real-time log monitoring."""
        event_manager = EventManager()
        monitor = LogMonitor(event_manager)
        
        received_events = []
        
        def event_handler(event):
            received_events.append(event)
        
        event_manager.subscribe("log_entry", event_handler)
        
        # Start monitoring
        monitor.start_monitoring(temp_log_file)
        
        # Write to log file
        with open(temp_log_file, 'a') as f:
            f.write("Test log entry\n")
        
        # Wait for processing
        import time
        time.sleep(0.1)
        
        # Verify event was received
        assert len(received_events) > 0
        
        monitor.stop_monitoring()
```

### Performance Testing

```python
import pytest
import time
from honeypot_monitor.services.threat_analyzer import ThreatAnalyzer

class TestPerformance:
    def test_analysis_performance(self):
        """Test threat analysis performance."""
        analyzer = ThreatAnalyzer()
        
        # Generate test data
        test_entries = self.generate_test_entries(1000)
        
        start_time = time.time()
        
        for entry in test_entries:
            analyzer.analyze_entry(entry)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 1000 entries in under 1 second
        assert processing_time < 1.0
        
        entries_per_second = len(test_entries) / processing_time
        assert entries_per_second > 1000
```

### Mocking External Dependencies

```python
from unittest.mock import Mock, patch
import pytest

class TestIRCNotifier:
    @patch('honeypot_monitor.services.irc_notifier.irc')
    def test_send_alert(self, mock_irc):
        """Test IRC alert sending with mocked IRC library."""
        mock_client = Mock()
        mock_irc.client.SimpleIRCClient.return_value = mock_client
        
        notifier = IRCNotifier()
        notifier.connect("irc.test.com", "#test", "test-bot")
        
        result = notifier.send_alert("TEST", "Test message")
        
        assert result is True
        mock_client.privmsg.assert_called_once()
```

## Code Quality

### Code Formatting

Use Black for consistent code formatting:

```bash
# Format all code
black src/ tests/

# Check formatting
black --check src/ tests/
```

### Linting

Use flake8 for code linting:

```bash
# Run linting
flake8 src/ tests/

# Configuration in setup.cfg
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = venv/
```

### Type Checking

Use mypy for static type checking:

```bash
# Run type checking
mypy src/

# Configuration in mypy.ini
[mypy]
python_version = 3.8
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
```

### Import Sorting

Use isort for import organization:

```bash
# Sort imports
isort src/ tests/

# Configuration in setup.cfg
[tool:isort]
profile = black
multi_line_output = 3
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 22.10.0
    hooks:
      - id: black
  
  - repo: https://github.com/pycqa/flake8
    rev: 5.0.4
    hooks:
      - id: flake8
  
  - repo: https://github.com/pycqa/isort
    rev: 5.10.1
    hooks:
      - id: isort
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v0.991
    hooks:
      - id: mypy
```

## Contributing

### Development Workflow

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/new-feature`
3. **Make changes** with tests
4. **Run quality checks**: `make lint test`
5. **Commit changes**: `git commit -m "Add new feature"`
6. **Push branch**: `git push origin feature/new-feature`
7. **Create pull request**

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(analyzer): add custom rule support

Add support for user-defined threat detection rules
with YAML configuration format.

Closes #123
```

### Pull Request Guidelines

- **Clear description** of changes
- **Tests included** for new functionality
- **Documentation updated** if needed
- **Code quality checks** passing
- **No breaking changes** without discussion

## API Reference

### Core Interfaces

#### AnalyzerInterface

```python
from abc import ABC, abstractmethod
from typing import Optional
from honeypot_monitor.models.log_entry import LogEntry
from honeypot_monitor.models.threat_assessment import ThreatAssessment

class AnalyzerInterface(ABC):
    @abstractmethod
    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAssessment]:
        """Analyze a log entry for threats."""
        pass
```

#### LogParserInterface

```python
from abc import ABC, abstractmethod
from typing import Optional
from honeypot_monitor.models.log_entry import LogEntry

class LogParserInterface(ABC):
    @abstractmethod
    def parse_entry(self, line: str) -> Optional[LogEntry]:
        """Parse a log line into a LogEntry."""
        pass
```

#### NotifierInterface

```python
from abc import ABC, abstractmethod
from honeypot_monitor.models.threat_assessment import ThreatAssessment

class NotifierInterface(ABC):
    @abstractmethod
    def send_alert(self, alert_type: str, message: str) -> bool:
        """Send a generic alert."""
        pass
    
    @abstractmethod
    def send_threat_alert(self, threat: ThreatAssessment, source_ip: str) -> bool:
        """Send a threat-specific alert."""
        pass
```

### Event System

#### Event Types

```python
from enum import Enum

class EventType(Enum):
    LOG_ENTRY = "log_entry"
    THREAT_DETECTED = "threat_detected"
    NEW_HOST = "new_host"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    ALERT_SENT = "alert_sent"
```

#### Event Manager API

```python
class EventManager:
    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        """Subscribe to events of a specific type."""
    
    def unsubscribe(self, event_type: EventType, callback: Callable) -> None:
        """Unsubscribe from events."""
    
    def publish(self, event_type: EventType, data: Any, source: str = None) -> bool:
        """Publish an event."""
    
    def publish_log_entry(self, log_entry: LogEntry) -> bool:
        """Publish a log entry event."""
    
    def publish_threat_detected(self, threat: ThreatAssessment, source_ip: str, log_entry: LogEntry) -> bool:
        """Publish a threat detection event."""
```

This developer guide provides comprehensive information for extending and contributing to the Honeypot Monitor CLI application. It covers the architecture, development practices, and APIs needed to effectively work with the codebase.