#!/bin/bash
# Unified launcher script for honeypot-monitor
# Supports both simple TUI and full application with log path customization

INSTALL_DIR="/home/cowrie/.honeypot-monitor"
VENV_DIR="/home/cowrie/.honeypot-monitor/venv"

# Default log path (will be checked for existence)
DEFAULT_LOG_PATH="/opt/kippo/log/kippo.log"

# Process command line options
SIMPLE_MODE=false
LOG_PATH=""
CONFIG_PATH=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Honeypot Monitor CLI launcher"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message and exit"
    echo "  -s, --simple            Use simple TUI mode (lightweight version)"
    echo "  -l, --log-path PATH     Specify custom log file path"
    echo "  -c, --config PATH       Specify custom config file path (full mode only)"
    echo
    echo "Examples:"
    echo "  $0                       # Run full application with default log path"
    echo "  $0 -s                    # Run simple TUI with default log path"
    echo "  $0 --log-path /var/log/cowrie/cowrie.log  # Use custom log path"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--simple)
            SIMPLE_MODE=true
            shift
            ;;
        -l|--log-path)
            LOG_PATH="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # If the argument doesn't match any option, assume it's a log path
            if [[ -z "$LOG_PATH" && -f "$1" ]]; then
                LOG_PATH="$1"
                shift
            else
                echo "Unknown option: $1"
                usage
                exit 1
            fi
            ;;
    esac
done

# Activate virtual environment if it exists
if [ -d "$VENV_DIR" ]; then
    source "$VENV_DIR/bin/activate"
fi

# Use provided log path or default
if [ -z "$LOG_PATH" ]; then
    LOG_PATH="$DEFAULT_LOG_PATH"
fi

# Check if log file exists
if [ ! -f "$LOG_PATH" ]; then
    echo "Log file not found: $LOG_PATH"
    exit 1
fi

# Launch the application
if [ "$SIMPLE_MODE" = true ]; then
    # Launch simple TUI
    echo "Starting simple honeypot monitor with log path: $LOG_PATH"
    if [ -f "$INSTALL_DIR/simple_tui.py" ]; then
        python "$INSTALL_DIR/simple_tui.py" --log-path "$LOG_PATH"
    else
        python "$(dirname "$0")/simple_tui.py" --log-path "$LOG_PATH"
    fi
else
    # Launch full application
    echo "Starting honeypot monitor with log path: $LOG_PATH"
    CONFIG_ARGS=""
    if [ -n "$CONFIG_PATH" ]; then
        CONFIG_ARGS="--config $CONFIG_PATH"
    fi
    
    if [ -f "$INSTALL_DIR/src/honeypot_monitor/main.py" ]; then
        python -m honeypot_monitor.main --log-path "$LOG_PATH" $CONFIG_ARGS
    else
        # Try to run from current directory
        PYTHONPATH="$(dirname "$0")" python -m honeypot_monitor.main --log-path "$LOG_PATH" $CONFIG_ARGS
    fi
fi