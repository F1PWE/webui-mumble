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
    
    # Remove any existing mumble-webui config
    rm -f /etc/nginx/sites-enabled/mumble-webui
    rm -f /etc/nginx/sites-available/mumble-webui
    
    # Backup existing default config if it exists and hasn't been backed up
    if [ -f /etc/nginx/sites-enabled/default ] && [ ! -f /etc/nginx/sites-enabled/default.bak ]; then
        echo "📑 Backing up default Nginx config..."
        cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak
    fi
    
    # Check for existing configurations with the same server_name
    local hostname=$(hostname)
    echo "🔍 Checking for conflicting Nginx configurations..."
    if grep -r "server_name.*$hostname" /etc/nginx/sites-enabled/ >/dev/null 2>&1; then
        echo "⚠️  Warning: Found existing configuration for $hostname"
        echo "   You may need to manually resolve server_name conflicts"
    fi
    
    # Generate nginx configuration
    echo "📝 Generating Nginx configuration..."
    cat > /etc/nginx/sites-available/mumble-webui << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $hostname;

    access_log /var/log/nginx/mumble_access.log;
    error_log /var/log/nginx/mumble_error.log debug;

    root /opt/webui-mumble;
    index index.html;

    # Serve static files
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # WebSocket proxy
    location /mumble {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        
        # WebSocket headers
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket timeouts
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_connect_timeout 86400;
        
        # WebSocket specific
        proxy_buffering off;
        proxy_cache off;
        
        # Error handling
        proxy_intercept_errors on;
        error_page 502 503 504 /50x.html;
    }

    # Error pages
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
EOF
    
    # Create symlink
    ln -sf /etc/nginx/sites-available/mumble-webui /etc/nginx/sites-enabled/
    
    # Test nginx configuration
    echo "🔍 Testing Nginx configuration..."
    if ! nginx -t; then
        echo "❌ Nginx configuration test failed"
        return 1
    fi
    
    # Reload nginx
    echo "🔄 Reloading Nginx..."
    systemctl reload nginx
    
    echo "✅ Nginx configuration complete"
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

# Function to check system configuration
check_system() {
    echo "🔍 Checking system configuration..."
    
    # Check if port 8080 is already in use
    if netstat -tuln | grep -q ":8080 "; then
        echo "⚠️  Port 8080 is in use. Checking process..."
        local pid=$(lsof -t -i:8080)
        if [ -n "$pid" ]; then
            local pname=$(ps -p $pid -o comm=)
            if [[ "$pname" == "mumble-we"* ]]; then
                echo "📋 Found existing mumble-webui process (PID: $pid)"
                echo "🔄 Stopping existing process..."
                systemctl stop mumble-webui
                sleep 2
                
                # Double check if process is still running
                if kill -0 $pid 2>/dev/null; then
                    echo "⚠️  Process still running, forcing stop..."
                    kill -9 $pid
                    sleep 1
                fi
            else
                echo "❌ Port 8080 is used by another process: $pname"
                echo "   Please stop this process before continuing"
                exit 1
            fi
        fi
    fi
    
    # Check if required directories exist
    for dir in "/var/log/nginx" "/var/log/mumble-webui"; do
        if [ ! -d "$dir" ]; then
            echo "📁 Creating missing directory: $dir"
            mkdir -p "$dir"
        fi
    done
    
    # Clean up any leftover files
    echo "🧹 Cleaning up old files..."
    rm -f /opt/webui-mumble/mumble-webui-server
    
    # Check nginx logs permissions
    if [ -d "/var/log/nginx" ]; then
        chown -R www-data:adm /var/log/nginx
        chmod -R 755 /var/log/nginx
    fi
    
    # Check mumble-webui service status
    if systemctl is-active mumble-webui >/dev/null 2>&1; then
        echo "🔄 Stopping existing mumble-webui service..."
        systemctl stop mumble-webui
        sleep 2
    fi
    
    # Check if nginx is running
    if ! systemctl is-active nginx >/dev/null 2>&1; then
        echo "🔄 Starting nginx service..."
        systemctl start nginx
    fi
    
    echo "✅ System check complete"
}

# Function to verify services
verify_services() {
    echo "🔍 Verifying services..."
    local errors=0
    
    # Check nginx
    if ! systemctl is-active nginx >/dev/null 2>&1; then
        echo "❌ Nginx is not running"
        echo "   Try: systemctl start nginx"
        ((errors++))
    else
        echo "✅ Nginx is running"
    fi
    
    # Check mumble-webui
    if ! systemctl is-active mumble-webui >/dev/null 2>&1; then
        echo "❌ Mumble WebUI service is not running"
        echo "   Check logs: journalctl -u mumble-webui -n 50"
        ((errors++))
    else
        echo "✅ Mumble WebUI service is running"
    fi
    
    # Check port 8080
    if ! netstat -tuln | grep -q ":8080 "; then
        echo "❌ No service listening on port 8080"
        ((errors++))
    else
        echo "✅ Port 8080 is active"
    fi
    
    # Check nginx config
    if ! nginx -t >/dev/null 2>&1; then
        echo "❌ Nginx configuration test failed"
        ((errors++))
    else
        echo "✅ Nginx configuration is valid"
    fi
    
    # Return status
    return $errors
}

# Function to perform complete cleanup
cleanup_all() {
    echo "🧹 Performing complete cleanup..."
    
    # Stop services
    echo "⏹️  Stopping services..."
    systemctl stop mumble-webui 2>/dev/null || true
    systemctl disable mumble-webui 2>/dev/null || true
    
    # Kill any remaining processes
    local pids=$(pgrep -f "mumble-we")
    if [ -n "$pids" ]; then
        echo "🔄 Killing remaining processes..."
        echo "   PIDs: $pids"
        for pid in $pids; do
            kill -9 $pid 2>/dev/null || true
        done
        sleep 1
    fi
    
    # Check port 8080
    local port_pid=$(lsof -t -i:8080 2>/dev/null)
    if [ -n "$port_pid" ]; then
        echo "🔄 Freeing port 8080..."
        kill -9 $port_pid 2>/dev/null || true
        sleep 1
    fi
    
    # Remove files
    echo "🗑️  Removing files..."
    rm -f /etc/systemd/system/mumble-webui.service
    rm -f /etc/nginx/sites-enabled/mumble-webui
    rm -f /etc/nginx/sites-available/mumble-webui
    rm -rf /opt/webui-mumble/*
    
    # Remove logs
    echo "🗑️  Cleaning logs..."
    rm -f /var/log/mumble-webui/*
    rm -f /var/log/nginx/mumble_*.log
    
    # Restore nginx config
    if [ -f /etc/nginx/sites-enabled/default.bak ]; then
        echo "↩️  Restoring nginx config..."
        mv /etc/nginx/sites-enabled/default.bak /etc/nginx/sites-enabled/default
        systemctl reload nginx
    fi
    
    # Reload systemd
    echo "🔄 Reloading systemd..."
    systemctl daemon-reload
    
    # Verify cleanup
    echo "🔍 Verifying cleanup..."
    local errors=0
    
    if pgrep -f "mumble-we" > /dev/null; then
        echo "⚠️  Warning: Some mumble-webui processes still running"
        ((errors++))
    fi
    
    if lsof -i :8080 > /dev/null 2>&1; then
        echo "⚠️  Warning: Port 8080 still in use"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        echo "✅ Cleanup complete - system is clean"
    else
        echo "⚠️  Cleanup completed with warnings"
        echo "   You may need to reboot the system"
    fi
    
    exit 0
}

# Process command line arguments
process_args() {
    case "$1" in
        --cleanup)
            check_root
            cleanup_all
            ;;
        "")
            # No arguments, run main
            main
            ;;
        *)
            echo "❌ Unknown argument: $1"
            echo "Usage: $0 [--cleanup]"
            exit 1
            ;;
    esac
}

# Call process_args with the first argument
process_args "$1"