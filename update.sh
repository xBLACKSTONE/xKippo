#!/bin/bash

# Honeypot Monitor CLI Update Script
# Updates the application code while preserving configuration and installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables - allow override via environment or detect installation
if [ -n "$HONEYPOT_INSTALL_DIR" ]; then
    INSTALL_DIR="$HONEYPOT_INSTALL_DIR"
elif [ -d "$HOME/.honeypot-monitor" ]; then
    INSTALL_DIR="$HOME/.honeypot-monitor"
elif [ -d "/home/cowrie/.honeypot-monitor" ]; then
    INSTALL_DIR="/home/cowrie/.honeypot-monitor"
else
    # Default fallback
    INSTALL_DIR="$HOME/.honeypot-monitor"
fi

VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="$INSTALL_DIR/config"
BACKUP_DIR="$INSTALL_DIR/backup"

# Helper functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Honeypot Monitor CLI Updater  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if honeypot monitor is installed
check_installation() {
    print_step "Checking existing installation..."
    
    # Try to find installation in common locations
    if [ ! -d "$INSTALL_DIR" ]; then
        print_warning "Installation not found at $INSTALL_DIR"
        
        # Try alternative locations
        for alt_dir in "/home/cowrie/.honeypot-monitor" "$HOME/.honeypot-monitor" "/opt/honeypot-monitor"; do
            if [ -d "$alt_dir" ]; then
                print_info "Found installation at $alt_dir"
                INSTALL_DIR="$alt_dir"
                VENV_DIR="$INSTALL_DIR/venv"
                CONFIG_DIR="$INSTALL_DIR/config"
                BACKUP_DIR="$INSTALL_DIR/backup"
                break
            fi
        done
        
        if [ ! -d "$INSTALL_DIR" ]; then
            print_error "Honeypot Monitor CLI installation not found"
            print_error "Searched locations:"
            print_error "  - $HOME/.honeypot-monitor"
            print_error "  - /home/cowrie/.honeypot-monitor"
            print_error "  - /opt/honeypot-monitor"
            print_error ""
            print_error "Please run the install.sh script first or set HONEYPOT_INSTALL_DIR environment variable"
            exit 1
        fi
    fi
    
    if [ ! -d "$VENV_DIR" ]; then
        print_error "Virtual environment not found at $VENV_DIR"
        print_error "Please run the install.sh script first"
        exit 1
    fi
    
    print_success "Installation found at $INSTALL_DIR"
}

# Check if we're in the source directory
check_source_directory() {
    print_step "Checking source directory..."
    
    if [ ! -f "setup.py" ] || [ ! -f "requirements.txt" ] || [ ! -d "src/honeypot_monitor" ]; then
        print_error "This script must be run from the honeypot monitor source directory"
        print_error "Make sure you're in the directory containing setup.py and src/"
        exit 1
    fi
    
    print_success "Source directory verified"
}

# Backup current configuration
backup_config() {
    print_step "Backing up current configuration..."
    
    # Create backup directory with timestamp
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    CURRENT_BACKUP_DIR="$BACKUP_DIR/config_$TIMESTAMP"
    
    mkdir -p "$CURRENT_BACKUP_DIR"
    
    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR"/* "$CURRENT_BACKUP_DIR/" 2>/dev/null || true
        print_success "Configuration backed up to $CURRENT_BACKUP_DIR"
    else
        print_info "No existing configuration to backup"
    fi
}

# Stop the service if running
stop_service() {
    print_step "Checking for running services..."
    
    # Check if systemd service exists and is running
    if systemctl --user is-active honeypot-monitor.service >/dev/null 2>&1; then
        print_info "Stopping honeypot-monitor service..."
        systemctl --user stop honeypot-monitor.service
        SERVICE_WAS_RUNNING=true
    else
        SERVICE_WAS_RUNNING=false
        print_info "No running service detected"
    fi
}

# Update the application
update_application() {
    print_step "Updating application code..."
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip
    
    # Clean up any existing build artifacts
    print_info "Cleaning build artifacts..."
    rm -rf build/ dist/ *.egg-info src/*.egg-info
    
    # Copy test files for debugging
    if [ -f "test_cowrie_parsing.py" ]; then
        cp test_cowrie_parsing.py "$INSTALL_DIR/"
        print_info "Copied parsing test script"
    fi
    
    if [ -f "test_log_monitor.py" ]; then
        cp test_log_monitor.py "$INSTALL_DIR/"
        print_info "Copied log monitor test script"
    fi
    
    # Install updated package
    print_info "Installing updated package..."
    pip install -e . --upgrade --force-reinstall
    
    if [ $? -eq 0 ]; then
        print_success "Application updated successfully"
    else
        print_warning "Editable install failed, trying alternative method..."
        
        # Fallback: install dependencies directly and copy files
        print_info "Installing dependencies from requirements.txt..."
        pip install -r requirements.txt --upgrade
        
        if [ $? -eq 0 ]; then
            print_info "Copying updated source files..."
            # Copy source files to the virtual environment
            SITE_PACKAGES="$VENV_DIR/lib/python*/site-packages"
            if [ -d "$SITE_PACKAGES" ]; then
                # Find the actual site-packages directory
                ACTUAL_SITE_PACKAGES=$(find "$VENV_DIR/lib" -name "site-packages" -type d | head -1)
                if [ -n "$ACTUAL_SITE_PACKAGES" ]; then
                    rm -rf "$ACTUAL_SITE_PACKAGES/honeypot_monitor" 2>/dev/null || true
                    cp -r src/honeypot_monitor "$ACTUAL_SITE_PACKAGES/"
                    print_success "Source files updated successfully"
                else
                    print_error "Could not find site-packages directory"
                    return 1
                fi
            else
                print_error "Could not locate site-packages directory"
                return 1
            fi
        else
            print_error "Failed to install dependencies"
            return 1
        fi
    fi
    
    # Verify critical dependencies
    print_info "Verifying dependencies..."
    python -c "import psutil, textual, watchdog, yaml" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_success "All dependencies verified"
    else
        print_warning "Some dependencies may need attention"
    fi
}

# Restore configuration
restore_config() {
    print_step "Preserving configuration..."
    
    # The configuration should already be preserved since we're only updating code
    # But let's make sure the config directory exists
    mkdir -p "$CONFIG_DIR"
    
    if [ -f "$CONFIG_DIR/config.yaml" ]; then
        print_success "Configuration preserved"
    else
        print_warning "No configuration file found - you may need to reconfigure"
    fi
}

# Start the service if it was running
start_service() {
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        print_step "Restarting honeypot-monitor service..."
        systemctl --user start honeypot-monitor.service
        
        if systemctl --user is-active honeypot-monitor.service >/dev/null 2>&1; then
            print_success "Service restarted successfully"
        else
            print_warning "Service failed to start - check logs with: journalctl --user -u honeypot-monitor.service"
        fi
    fi
}

# Show update summary
show_summary() {
    echo
    print_success "Update completed successfully!"
    echo
    print_info "Summary:"
    print_info "  - Application code updated"
    print_info "  - Dependencies verified"
    print_info "  - Configuration preserved"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        print_info "  - Service restarted"
    fi
    echo
    print_info "Usage:"
    if [ -f "$HOME/.local/bin/honeypot-monitor" ]; then
        print_info "  honeypot-monitor                    # Start the TUI"
    else
        print_info "  $INSTALL_DIR/honeypot-monitor       # Start the TUI"
    fi
    echo
    print_info "Configuration: $CONFIG_DIR/config.yaml"
    print_info "Logs: journalctl --user -u honeypot-monitor.service (if using systemd)"
    echo
}

# Main update function
main() {
    print_header
    
    print_info "This script will update Honeypot Monitor CLI while preserving your configuration."
    echo
    
    # Run update steps
    check_installation
    check_source_directory
    backup_config
    stop_service
    update_application
    restore_config
    start_service
    show_summary
}

# Handle script interruption
cleanup() {
    echo
    print_warning "Update interrupted!"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        print_info "Attempting to restart service..."
        systemctl --user start honeypot-monitor.service >/dev/null 2>&1 || true
    fi
    exit 1
}

trap cleanup INT TERM

# Run main function
main "$@"