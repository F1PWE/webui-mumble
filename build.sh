#!/bin/bash

# Check if we're running in bash
if [ -z "$BASH_VERSION" ]; then
    echo "⚠️  Please run this script with bash: bash build.sh"
    exit 1
fi

# Exit on any error
set -e

echo "🚀 Starting Mumble WebUI build process..."

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "❌ Please run as root (use sudo bash build.sh)"
        exit 1
    fi
}

# Function for error handling
handle_error() {
    local exit_code=$?
    echo "❌ Error occurred in build script (exit code: $exit_code)"
    cleanup
}

# Function to install dependencies
install_deps() {
    echo "📦 Installing dependencies..."
    apt-get update
    apt-get install -y \
        build-essential \
        libssl-dev \
        libwebsockets-dev \
        libjansson-dev \
        nginx \
        pkg-config \
        git \
        curl
}

# Function to create necessary directories
create_dirs() {
    echo "📁 Creating directories..."
    mkdir -p /opt/webui-mumble
    mkdir -p /var/log/mumble-webui
}

# Function to build the server
build_server() {
    echo "🔨 Building server..."
    
    # Stop the service if it's running
    echo "⏸️  Stopping service for update..."
    systemctl stop mumble-webui 2>/dev/null || true
    
    # Small delay to ensure process is fully stopped
    sleep 2
    
    # Clean and build
    make clean
    make
    
    # Remove old binary if it exists
    rm -f /opt/webui-mumble/mumble-webui-server
    
    # Copy new files
    echo "📋 Copying new files..."
    cp mumble-webui-server /opt/webui-mumble/
    cp -r src/client/* /opt/webui-mumble/
    
    echo "✨ Build and copy complete"
}

# Function to set up systemd service
setup_service() {
    echo "⚙️ Setting up systemd service..."
    
    # Stop and disable existing service if it exists
    if systemctl is-active mumble-webui >/dev/null 2>&1; then
        echo "⏹️  Stopping existing service..."
        systemctl stop mumble-webui
        systemctl disable mumble-webui
    fi
    
    # Create mumble-web group if it doesn't exist
    echo "👥 Setting up user groups..."
    groupadd -f mumble-web
    
    # Add www-data to mumble-web group
    usermod -a -G mumble-web www-data
    
    # Copy service file
    echo "📄 Installing service file..."
    cp mumble-webui.service /etc/systemd/system/
    
    # Reload systemd
    echo "🔄 Reloading systemd..."
    systemctl daemon-reload
    
    # Enable and start service
    echo "▶️  Starting service..."
    systemctl enable mumble-webui
    systemctl restart mumble-webui
    
    # Check service status
    echo "🔍 Checking service status..."
    if ! systemctl is-active mumble-webui >/dev/null 2>&1; then
        echo "❌ Service failed to start. Check logs with: journalctl -u mumble-webui -n 50"
        return 1
    fi
    
    echo "✅ Service setup complete"
}

# Function to configure nginx
setup_nginx() {
    echo "🌐 Configuring Nginx..."
    
    # Backup existing config if it exists
    if [ -f /etc/nginx/sites-enabled/default ]; then
        mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak
    fi
    
    # Copy our nginx config
    cp nginx.conf /etc/nginx/sites-available/mumble-webui
    ln -sf /etc/nginx/sites-available/mumble-webui /etc/nginx/sites-enabled/
    
    # Test and reload nginx
    nginx -t
    systemctl reload nginx
}

# Function to set permissions
set_permissions() {
    echo "🔒 Setting permissions..."
    chown -R www-data:mumble-web /opt/webui-mumble
    chmod -R 750 /opt/webui-mumble
    chown -R www-data:mumble-web /var/log/mumble-webui
    chmod -R 750 /var/log/mumble-webui
}

# Function to clean up on failure
cleanup() {
    echo "🧹 Cleaning up..."
    
    # Stop services
    systemctl stop mumble-webui 2>/dev/null || true
    systemctl disable mumble-webui 2>/dev/null || true
    
    # Remove files
    rm -f /etc/systemd/system/mumble-webui.service
    rm -f /etc/nginx/sites-enabled/mumble-webui
    rm -f /etc/nginx/sites-available/mumble-webui
    
    # Restore nginx config
    if [ -f /etc/nginx/sites-enabled/default.bak ]; then
        mv /etc/nginx/sites-enabled/default.bak /etc/nginx/sites-enabled/default
        systemctl reload nginx
    fi
    
    echo "❌ Build failed! Cleanup complete."
    exit 1
}

# Set up error handling (bash-specific)
trap handle_error ERR

# Main build process
main() {
    echo "🎯 Starting main build process..."
    
    check_root
    install_deps
    create_dirs
    build_server
    setup_service
    setup_nginx
    set_permissions
    
    echo "✅ Build complete! Services should be running."
    echo "📝 Check logs with: journalctl -u mumble-webui -f"
    echo "🌐 Access the web interface at: https://$(hostname)"
}

# Run main function
main 