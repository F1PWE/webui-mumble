#!/bin/sh

# Create directory structure
mkdir -p src/server
mkdir -p src/client

# Create necessary files if they don't exist
touch src/client/app.js
touch src/server/main.c

# Install dependencies based on the package manager
if command -v apt-get >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y build-essential cmake libssl-dev \
        libwebsockets-dev libjansson-dev
elif command -v pacman >/dev/null; then
    sudo pacman -Sy base-devel cmake openssl \
        libwebsockets jansson
elif command -v dnf >/dev/null; then
    sudo dnf groupinstall "Development Tools"
    sudo dnf install cmake openssl-devel \
        libwebsockets-devel jansson-devel
fi

# Make the script executable
chmod +x setup.sh

# Build the server
make clean
make

echo "Setup completed. Directory structure created and dependencies installed."
echo "Next steps:"
echo "1. Start the Mumble server"
echo "2. Run ./mumble-webui-server"
echo "3. Open index.html in your browser" 