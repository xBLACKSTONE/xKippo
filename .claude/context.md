# Honeypot Monitor CLI - Project Context

## Project Purpose
The Honeypot Monitor CLI is a security tool that monitors Kippo honeypot logs for suspicious activities. It's designed to help security professionals analyze potential threats in real-time through a terminal-based interface.

## Key Components

### Log Monitoring and Parsing
- Real-time monitoring of Kippo honeypot logs
- Parsing of log entries into structured data

### Threat Analysis
- Analysis of log entries to detect potential threats
- Categorization and scoring of detected threats

### Notification System
- IRC-based notification for real-time alerts
- Configurable alert thresholds and types

### Terminal UI
- Interactive terminal user interface using Textual framework
- Multiple panels for different views (dashboard, log viewer, analysis)

## Architecture

The application follows a layered architecture:
1. Data layer: Models, interfaces, and storage
2. Service layer: Business logic and processing
3. Application layer: Event management and coordination
4. Presentation layer: TUI components and CLI interface

## Development Workflows

- Test-driven development
- Code quality checks using black, flake8, mypy
- Comprehensive testing including unit, integration, and performance tests