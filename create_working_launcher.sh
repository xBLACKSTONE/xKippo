#!/bin/bash
# Create a launcher for the working simple TUI version

INSTALL_DIR="/home/cowrie/.honeypot-monitor"
VENV_DIR="/home/cowrie/.honeypot-monitor/venv"

echo "Creating working honeypot monitor launcher..."

# Create the working launcher
cat > "$INSTALL_DIR/honeypot-monitor-working" << 'EOF'
#!/bin/bash
# Working Honeypot Monitor CLI Launcher

INSTALL_DIR="/home/cowrie/.honeypot-monitor"
VENV_DIR="/home/cowrie/.honeypot-monitor/venv"

# Use virtual environment Python directly
# Allow passing log path as parameter or use default
LOG_PATH=${1:-"/opt/kippo/log/kippo.log"}
"$VENV_DIR/bin/python" "$INSTALL_DIR/simple_tui.py" --log-path "$LOG_PATH"
EOF

chmod +x "$INSTALL_DIR/honeypot-monitor-working"

# Create symlink if local bin exists
if [ -d "$HOME/.local/bin" ]; then
    ln -sf "$INSTALL_DIR/honeypot-monitor-working" "$HOME/.local/bin/honeypot-monitor-working"
    echo "✅ Created launcher at $HOME/.local/bin/honeypot-monitor-working"
else
    echo "✅ Created launcher at $INSTALL_DIR/honeypot-monitor-working"
fi

echo ""
echo "🎉 Working honeypot monitor is ready!"
echo ""
echo "To run:"
echo "  honeypot-monitor-working    (if in PATH)"
echo "  OR"
echo "  $INSTALL_DIR/honeypot-monitor-working"
echo ""
echo "Controls:"
echo "  r - Refresh data"
echo "  q - Quit"
echo "  Click buttons to refresh/quit"