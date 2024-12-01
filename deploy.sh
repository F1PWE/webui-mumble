#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Install required packages
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx

# Create web directory
mkdir -p /var/www/webui-mumble
cp -r src/client/* /var/www/webui-mumble/src/client/

# Install Nginx config
cp nginx.conf /etc/nginx/sites-available/nimmerchat.xyz
ln -sf /etc/nginx/sites-available/nimmerchat.xyz /etc/nginx/sites-enabled/

# Remove default Nginx config
rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
nginx -t

# Get SSL certificate
certbot --nginx -d nimmerchat.xyz --non-interactive --agree-tos --email admin@nimmerchat.xyz

# Restart Nginx
systemctl restart nginx

# Build and start the WebUI server
make clean
make
./mumble-webui-server &

echo "Deployment complete!"
echo "Your WebUI is now available at https://nimmerchat.xyz" 