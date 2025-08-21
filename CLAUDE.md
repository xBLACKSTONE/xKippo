# Project: Honeypot Monitor CLI

This file helps Claude understand the project structure and provides useful commands and context.

## Project Overview

Honeypot Monitor CLI is a terminal-based monitoring application for Kippo honeypot traffic analysis. It provides real-time monitoring, threat analysis, and IRC notifications through an intuitive terminal user interface (TUI) similar to lazydocker. The tool runs locally on the same host as the honeypot, providing easy installation and deployment through an interactive setup script.

## Key Features

- Real-time monitoring of Kippo honeypot logs with live updates
- Interactive TUI with keyboard navigation and color-coded displays
- Threat analysis with automatic categorization and severity scoring
- IRC notifications for real-time alerts to designated channels
- Historical log data with search, filter, and export capabilities
- Session tracking to correlate activities across multiple sessions

## Project Structure

- `src/honeypot_monitor/`: Main application code
  - `main.py`: Application entry point
  - `interfaces/`: Abstract base classes and interfaces
    - `analyzer_interface.py`: Threat analyzer interface
    - `log_parser_interface.py`: Log parser interface
    - `monitor_interface.py`: Monitor interface
    - `notifier_interface.py`: Notifier interface
  - `models/`: Data models
    - `log_entry.py`: Log entry model
    - `session.py`: Session tracking model
    - `threat_assessment.py`: Threat assessment model
    - `irc_alert.py`: IRC alert model
    - `converters.py`: Model converters
  - `services/`: Business logic services
    - `log_monitor.py`: File monitoring service
    - `log_parser.py`: Log parsing service
    - `threat_analyzer.py`: Threat analysis service
    - `irc_notifier.py`: IRC notification service
    - `alert_manager.py`: Alert management service
    - `event_manager.py`: Event coordination service
    - `service_coordinator.py`: Service orchestration
    - `memory_manager.py`: Memory management
    - `performance_monitor.py`: Performance monitoring
  - `tui/`: Terminal UI components
    - `main_app.py`: Main TUI application
    - `dashboard.py`: Dashboard panel
    - `log_viewer.py`: Log viewer panel
    - `analysis_panel.py`: Analysis panel
    - `settings_panel.py`: Settings panel
    - `*.tcss`: Textual CSS files
  - `config/`: Configuration management
    - `config_manager.py`: Configuration loader
    - `settings.py`: Settings models

## Development Environment

- Python 3.8+
- Virtual environment recommended
- Dependencies:
  - `textual>=0.40.0`: Rich TUI framework
  - `watchdog>=3.0.0`: File system monitoring
  - `PyYAML>=6.0`: Configuration file parsing
  - `irc>=20.0.0`: IRC client library
  - `rich>=13.0.0`: Terminal formatting and colors
- Development dependencies:
  - `pytest>=7.0.0`: Testing framework
  - `pytest-cov>=4.0.0`: Coverage reporting
  - `black>=22.0.0`: Code formatting
  - `flake8>=5.0.0`: Code linting
  - `mypy>=1.0.0`: Type checking
  - `isort>=5.10.0`: Import sorting

## Commands

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### Running the Application

```bash
# Run directly
python -m honeypot_monitor.main

# Or if installed in dev mode
honeypot-monitor
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=honeypot_monitor --cov-report=html

# Run specific test categories
pytest tests/test_services/
pytest tests/test_models/
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

## Architecture

The application follows a layered architecture pattern:

```ascii
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

## TUI Navigation

The terminal interface provides several panels:

- **Dashboard**: Real-time activity feed and connection statistics
- **Log Viewer**: Browse and search historical logs with filtering
- **Analysis Panel**: View threat assessments and pattern analysis
- **Settings**: Configure monitoring and IRC settings

### Keyboard Shortcuts

- `Tab` / `Shift+Tab`: Navigate between panels
- `q` / `Ctrl+C`: Quit application
- `r`: Refresh current view
- `f`: Open filter dialog
- `s`: Open search
- `e`: Export current view
- `h`: Show help

## Workflow Tips

- Use TDD approach when implementing new features
- Follow the existing architecture patterns
- Create interfaces before implementation
- Respect the layered architecture
- Ensure comprehensive error handling
- Maintain performance with memory management
