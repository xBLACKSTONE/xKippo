#!/bin/bash
# Install script for honeypot-monitor launcher

INSTALL_DIR="/home/cowrie/.honeypot-monitor"
LOCAL_BIN="$HOME/.local/bin"

# Create installation directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Copy launcher script
cp "$(dirname "$0")/honeypot-monitor-launcher.sh" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/honeypot-monitor-launcher.sh"

# Create symbolic link in user's local bin if it exists
if [ -d "$LOCAL_BIN" ]; then
    ln -sf "$INSTALL_DIR/honeypot-monitor-launcher.sh" "$LOCAL_BIN/honeypot-monitor"
    echo "✅ Installed launcher as 'honeypot-monitor' in $LOCAL_BIN"
    echo "   You can now run the monitor with: honeypot-monitor"
else
    echo "✅ Installed launcher at $INSTALL_DIR/honeypot-monitor-launcher.sh"
fi

# Create a convenient wrapper for the simple mode
cat > "$INSTALL_DIR/honeypot-monitor-simple" << 'EOF'
#!/bin/bash
# Simple mode launcher for honeypot monitor
"$INSTALL_DIR/honeypot-monitor-launcher.sh" --simple "$@"
EOF

chmod +x "$INSTALL_DIR/honeypot-monitor-simple"

# Create symbolic link for simple mode
if [ -d "$LOCAL_BIN" ]; then
    ln -sf "$INSTALL_DIR/honeypot-monitor-simple" "$LOCAL_BIN/honeypot-monitor-simple"
    echo "✅ Installed simple mode launcher as 'honeypot-monitor-simple' in $LOCAL_BIN"
else
    echo "✅ Installed simple mode launcher at $INSTALL_DIR/honeypot-monitor-simple"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Usage:"
echo "  honeypot-monitor [OPTIONS]       - Full application"
echo "  honeypot-monitor-simple [OPTIONS] - Simple TUI"
echo ""
echo "Options:"
echo "  --log-path PATH     - Specify custom log path"
echo "  --config PATH       - Specify custom config (full mode only)"
echo ""