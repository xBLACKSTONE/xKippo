#!/bin/bash

# Honeypot Monitor CLI Installation Script
# Interactive installer with dependency checking and configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
INSTALL_DIR="$HOME/.honeypot-monitor"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="$INSTALL_DIR/config"
DEFAULT_KIPPO_PATHS=(
    "/opt/kippo/log/kippo.log"
    "/var/log/kippo/kippo.log"
    "/usr/local/kippo/log/kippo.log"
    "$HOME/kippo/log/kippo.log"
)

# Helper functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Honeypot Monitor CLI Installer${NC}"
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

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Prompt user with default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local result
    
    read -p "$prompt [$default]: " result
    echo "${result:-$default}"
}

# Prompt yes/no with default
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local result
    
    while true; do
        read -p "$prompt (y/n) [$default]: " result
        result="${result:-$default}"
        case "$result" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Check Python installation
check_python() {
    print_step "Checking Python installation..."
    
    if command_exists python3; then
        PYTHON_CMD="python3"
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_info "Found Python $PYTHON_VERSION"
        
        # Check if version is 3.8 or higher
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            print_success "Python version is compatible (3.8+)"
            return 0
        else
            print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
            return 1
        fi
    elif command_exists python; then
        PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
        if python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            PYTHON_CMD="python"
            print_info "Found Python $PYTHON_VERSION"
            print_success "Python version is compatible (3.8+)"
            return 0
        else
            print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
            return 1
        fi
    else
        print_error "Python is not installed or not in PATH"
        return 1
    fi
}

# Check pip installation
check_pip() {
    print_step "Checking pip installation..."
    
    if command_exists pip3; then
        PIP_CMD="pip3"
        print_success "Found pip3"
        return 0
    elif command_exists pip; then
        PIP_CMD="pip"
        print_success "Found pip"
        return 0
    else
        print_warning "pip is not installed, will attempt to install it"
        if command_exists apt-get; then
            if prompt_yes_no "Install pip using apt-get?" "y"; then
                sudo apt-get update
                sudo apt-get install -y python3-pip
                if command_exists pip3; then
                    PIP_CMD="pip3"
                    print_success "Successfully installed pip3"
                    return 0
                fi
            fi
        elif command_exists yum; then
            if prompt_yes_no "Install pip using yum?" "y"; then
                sudo yum install -y python3-pip
                if command_exists pip3; then
                    PIP_CMD="pip3"
                    print_success "Successfully installed pip3"
                    return 0
                fi
            fi
        elif command_exists brew; then
            if prompt_yes_no "Install pip using brew?" "y"; then
                brew install python3-pip
                if command_exists pip3; then
                    PIP_CMD="pip3"
                    print_success "Successfully installed pip3"
                    return 0
                fi
            fi
        else
            print_warning "Attempting to install pip using get-pip.py..."
            curl -s https://bootstrap.pypa.io/get-pip.py -o get-pip.py
            $PYTHON_CMD get-pip.py
            rm get-pip.py
            if command_exists pip3; then
                PIP_CMD="pip3"
                print_success "Successfully installed pip3"
                return 0
            elif command_exists pip; then
                PIP_CMD="pip"
                print_success "Successfully installed pip"
                return 0
            fi
        fi
        print_error "Failed to install pip. Please install it manually."
        return 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_step "Checking system dependencies..."
    
    # Check for required system packages
    local missing_deps=()
    
    if ! command_exists git; then
        missing_deps+=("git")
    fi
    
    # Additional dependencies that might be needed
    if command_exists apt-get; then
        # For psutil and other compiled dependencies
        if ! command_exists gcc; then
            missing_deps+=("gcc")
        fi
        if ! command_exists python3-dev || ! command_exists python3.8-dev; then
            missing_deps+=("python3-dev")
        fi
    elif command_exists yum; then
        if ! command_exists gcc; then
            missing_deps+=("gcc")
        fi
        if ! command_exists python3-devel; then
            missing_deps+=("python3-devel")
        fi
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_warning "Missing system dependencies: ${missing_deps[*]}"
        
        if command_exists apt-get; then
            if prompt_yes_no "Install missing dependencies using apt-get?" "y"; then
                sudo apt-get update
                sudo apt-get install -y "${missing_deps[@]}"
            fi
        elif command_exists yum; then
            if prompt_yes_no "Install missing dependencies using yum?" "y"; then
                sudo yum install -y "${missing_deps[@]}"
            fi
        elif command_exists brew; then
            if prompt_yes_no "Install missing dependencies using brew?" "y"; then
                brew install "${missing_deps[@]}"
            fi
        else
            print_error "Please install the following dependencies manually: ${missing_deps[*]}"
            return 1
        fi
    else
        print_success "All system dependencies are installed"
    fi
}

# Create virtual environment
create_venv() {
    print_step "Creating virtual environment..."
    
    if [ -d "$VENV_DIR" ]; then
        if prompt_yes_no "Virtual environment already exists. Recreate?" "n"; then
            rm -rf "$VENV_DIR"
        else
            print_info "Using existing virtual environment"
            return 0
        fi
    fi
    
    mkdir -p "$INSTALL_DIR"
    $PYTHON_CMD -m venv "$VENV_DIR"
    
    if [ $? -eq 0 ]; then
        print_success "Virtual environment created at $VENV_DIR"
    else
        print_error "Failed to create virtual environment"
        return 1
    fi
}

# Activate virtual environment
activate_venv() {
    source "$VENV_DIR/bin/activate"
    print_info "Activated virtual environment"
}

# Install Python dependencies
install_python_deps() {
    print_step "Installing Python dependencies..."
    
    # Upgrade pip first
    print_info "Upgrading pip..."
    $PIP_CMD install --upgrade pip
    
    # Install required packages explicitly before attempting to install the package
    print_info "Installing core dependencies..."
    $PIP_CMD install wheel setuptools
    
    # Install psutil and textual explicitly with possible build dependencies
    print_info "Installing psutil and textual..."
    $PIP_CMD install psutil textual
    
    # Install the package in development mode
    print_info "Installing honeypot-monitor and dependencies..."
    $PIP_CMD install -e .
    
    if [ $? -eq 0 ]; then
        print_success "Python dependencies installed successfully"
        
        # Verify critical dependencies are installed
        print_info "Verifying installation..."
        # Check each dependency separately for better error reporting
        for dep in psutil textual watchdog yaml; do
            print_info "Checking $dep..."
            python -c "import $dep" 2>/dev/null
            if [ $? -ne 0 ]; then
                print_warning "$dep may not be installed properly, attempting to reinstall..."
                pip install --upgrade $dep
                python -c "import $dep" 2>/dev/null
                if [ $? -ne 0 ]; then
                    print_error "Failed to install $dep. You may need to install development libraries."
                    if [ "$dep" = "psutil" ]; then
                        if command_exists apt-get; then
                            print_info "For psutil, you might need: sudo apt-get install python3-dev gcc"
                        elif command_exists yum; then
                            print_info "For psutil, you might need: sudo yum install python3-devel gcc"
                        fi
                    fi
                else
                    print_success "Successfully reinstalled $dep"
                fi
            else
                print_success "$dep is properly installed"
            fi
        done
    else
        print_error "Failed to install Python dependencies"
        print_error "Try running: pip install -r requirements.txt"
        return 1
    fi
}

# Detect Kippo installation
detect_kippo() {
    print_step "Detecting Kippo installation..."
    
    local found_paths=()
    
    for path in "${DEFAULT_KIPPO_PATHS[@]}"; do
        if [ -f "$path" ] || [ -d "$(dirname "$path")" ]; then
            found_paths+=("$path")
        fi
    done
    
    if [ ${#found_paths[@]} -gt 0 ]; then
        print_success "Found potential Kippo installations:"
        for i in "${!found_paths[@]}"; do
            echo "  $((i+1)). ${found_paths[$i]}"
        done
        echo "  $((${#found_paths[@]}+1)). Enter custom path"
        echo "  $((${#found_paths[@]}+2)). Skip for now"
        
        while true; do
            read -p "Select Kippo log path [1]: " choice
            choice="${choice:-1}"
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $((${#found_paths[@]}+2)) ]; then
                if [ "$choice" -le "${#found_paths[@]}" ]; then
                    KIPPO_LOG_PATH="${found_paths[$((choice-1))]}"
                    break
                elif [ "$choice" -eq $((${#found_paths[@]}+1)) ]; then
                    KIPPO_LOG_PATH=$(prompt_with_default "Enter Kippo log path" "/opt/kippo/log/kippo.log")
                    break
                else
                    KIPPO_LOG_PATH=""
                    print_info "Skipping Kippo configuration for now"
                    break
                fi
            else
                echo "Invalid choice. Please select a number between 1 and $((${#found_paths[@]}+2))"
            fi
        done
    else
        print_warning "No Kippo installations detected automatically"
        if prompt_yes_no "Would you like to specify a custom Kippo log path?" "y"; then
            KIPPO_LOG_PATH=$(prompt_with_default "Enter Kippo log path" "/opt/kippo/log/kippo.log")
        else
            KIPPO_LOG_PATH=""
            print_info "Skipping Kippo configuration for now"
        fi
    fi
}

# Create configuration
create_config() {
    print_step "Creating configuration..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Get IRC configuration
    if prompt_yes_no "Enable IRC notifications?" "n"; then
        IRC_ENABLED="true"
        IRC_SERVER=$(prompt_with_default "IRC server" "irc.libera.chat")
        IRC_PORT=$(prompt_with_default "IRC port" "6667")
        IRC_CHANNEL=$(prompt_with_default "IRC channel" "#security-alerts")
        IRC_NICKNAME=$(prompt_with_default "IRC nickname" "honeypot-monitor")
        IRC_SSL=$(prompt_yes_no "Use SSL?" "n" && echo "true" || echo "false")
    else
        IRC_ENABLED="false"
        IRC_SERVER="irc.libera.chat"
        IRC_PORT="6667"
        IRC_CHANNEL="#security-alerts"
        IRC_NICKNAME="honeypot-monitor"
        IRC_SSL="false"
    fi
    
    # Create configuration file
    cat > "$CONFIG_DIR/config.yaml" << EOF
honeypot:
  log_path: "${KIPPO_LOG_PATH:-/opt/kippo/log/kippo.log}"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 10000

analysis:
  threat_threshold: "medium"
  custom_rules_path: "$CONFIG_DIR/rules/"

irc:
  enabled: $IRC_ENABLED
  server: "$IRC_SERVER"
  port: $IRC_PORT
  channel: "$IRC_CHANNEL"
  nickname: "$IRC_NICKNAME"
  ssl: $IRC_SSL
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"

interface:
  theme: "dark"
  key_bindings: "default"
EOF
    
    # Create rules directory
    mkdir -p "$CONFIG_DIR/rules"
    
    print_success "Configuration created at $CONFIG_DIR/config.yaml"
}

# Create launcher script
create_launcher() {
    print_step "Creating launcher script..."
    
    cat > "$INSTALL_DIR/honeypot-monitor" << EOF
#!/bin/bash
# Honeypot Monitor CLI Launcher

INSTALL_DIR="$INSTALL_DIR"
VENV_DIR="$VENV_DIR"
CONFIG_DIR="$CONFIG_DIR"

# Use virtual environment Python directly (more reliable than source activate)
"\$VENV_DIR/bin/python" -m honeypot_monitor.main --config "\$CONFIG_DIR/config.yaml" "\$@"
EOF
    
    chmod +x "$INSTALL_DIR/honeypot-monitor"
    
    # Create symlink in user's local bin if it exists
    if [ -d "$HOME/.local/bin" ]; then
        ln -sf "$INSTALL_DIR/honeypot-monitor" "$HOME/.local/bin/honeypot-monitor"
        print_success "Created launcher at $HOME/.local/bin/honeypot-monitor"
    else
        print_info "Launcher created at $INSTALL_DIR/honeypot-monitor"
        print_info "Add $INSTALL_DIR to your PATH or create an alias to use 'honeypot-monitor' command"
    fi
}

# Create systemd service (optional)
create_service() {
    # Check if we're on a system that supports systemd
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_info "Skipping systemd service creation (macOS detected)"
        print_info "You can run the monitor manually or create a launchd service if needed"
        return 0
    fi
    
    if ! command_exists systemctl; then
        print_info "Skipping systemd service creation (systemctl not found)"
        return 0
    fi
    
    if prompt_yes_no "Create systemd service for background operation?" "n"; then
        print_step "Creating systemd service..."
        
        local service_file="$HOME/.config/systemd/user/honeypot-monitor.service"
        mkdir -p "$(dirname "$service_file")"
        
        cat > "$service_file" << EOF
[Unit]
Description=Honeypot Monitor CLI
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/honeypot-monitor --daemon
Restart=always
RestartSec=10
Environment=PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
EOF
        
        systemctl --user daemon-reload
        
        if prompt_yes_no "Enable and start the service now?" "n"; then
            systemctl --user enable honeypot-monitor.service
            systemctl --user start honeypot-monitor.service
            print_success "Service enabled and started"
        else
            print_info "Service created but not enabled. Use 'systemctl --user enable honeypot-monitor.service' to enable"
        fi
    fi
}

# Main installation function
main() {
    print_header
    
    print_info "This script will install Honeypot Monitor CLI and its dependencies."
    print_info "Installation directory: $INSTALL_DIR"
    echo
    
    if ! prompt_yes_no "Continue with installation?" "y"; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo
    
    # Check prerequisites
    if ! check_python; then
        print_error "Python check failed. Please install Python 3.8 or higher."
        exit 1
    fi
    
    if ! check_pip; then
        print_error "pip check failed. Please install pip."
        exit 1
    fi
    
    # Install system dependencies
    install_system_deps
    
    # Create and setup virtual environment
    create_venv
    activate_venv
    
    # Install Python dependencies
    install_python_deps
    
    # Detect Kippo and create configuration
    detect_kippo
    create_config
    
    # Create launcher and service
    create_launcher
    create_service
    
    echo
    print_success "Installation completed successfully!"
    echo
    print_info "Usage:"
    if [ -f "$HOME/.local/bin/honeypot-monitor" ]; then
        print_info "  honeypot-monitor                    # Start the TUI"
        print_info "  honeypot-monitor --help             # Show help"
    else
        print_info "  $INSTALL_DIR/honeypot-monitor       # Start the TUI"
        print_info "  $INSTALL_DIR/honeypot-monitor --help # Show help"
    fi
    echo
    print_info "Configuration file: $CONFIG_DIR/config.yaml"
    print_info "You can edit this file to customize settings."
    echo
    
    if [ -n "$KIPPO_LOG_PATH" ]; then
        if [ ! -f "$KIPPO_LOG_PATH" ]; then
            print_warning "Kippo log file not found at: $KIPPO_LOG_PATH"
            print_warning "Please update the configuration file with the correct path."
        fi
    fi
}

# Run main function
main "$@"