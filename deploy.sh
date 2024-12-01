#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Install required packages
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx

# Create service user
useradd -r -s /bin/false mumble-web
groupadd -f mumble-web

# Create directories
mkdir -p /var/www/webui-mumble/src/client
mkdir -p /opt/webui-mumble

# Copy files
cp -r src/client/* /var/www/webui-mumble/src/client/
cp mumble-webui-server /opt/webui-mumble/
cp mumble-webui.service /etc/systemd/system/

# Set permissions
chown -R mumble-web:mumble-web /opt/webui-mumble
chown -R www-data:www-data /var/www/webui-mumble

# Install Nginx config
cp nginx.conf /etc/nginx/sites-available/nimmerchat.xyz
ln -sf /etc/nginx/sites-available/nimmerchat.xyz /etc/nginx/sites-enabled/

# Remove default Nginx config
rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
nginx -t

# Get SSL certificate
certbot --nginx -d nimmerchat.xyz --non-interactive --agree-tos --email admin@nimmerchat.xyz

# Start services
systemctl daemon-reload
systemctl enable mumble-webui
systemctl start mumble-webui
systemctl restart nginx

echo "Deployment complete!"
echo "Your WebUI is now available at https://nimmerchat.xyz"
echo "Check service status with: systemctl status mumble-webui"