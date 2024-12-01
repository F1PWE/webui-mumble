#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Install required packages
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx libcap2-bin ssl-cert acl

# Create mumble-web group if it doesn't exist
if ! getent group mumble-web > /dev/null; then
    groupadd mumble-web
fi

# Add www-data to necessary groups
usermod -a -G ssl-cert www-data
usermod -a -G mumble-web www-data

# Create web directory and set permissions
mkdir -p /var/www/webui-mumble/src/client
cp -r src/client/* /var/www/webui-mumble/src/client/
chown -R www-data:www-data /var/www/webui-mumble

# Create application directory
mkdir -p /opt/webui-mumble
cp mumble-webui-server /opt/webui-mumble/
cp mumble-webui.service /etc/systemd/system/
chmod +x /opt/webui-mumble/mumble-webui-server
chown -R www-data:mumble-web /opt/webui-mumble

# Set capabilities for port binding
setcap 'cap_net_bind_service=+ep' /opt/webui-mumble/mumble-webui-server

# Install Nginx config
cp nginx.conf /etc/nginx/sites-available/nimmerchat.xyz
ln -sf /etc/nginx/sites-available/nimmerchat.xyz /etc/nginx/sites-enabled/

# Remove default Nginx config
rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
nginx -t

# Create log directory
mkdir -p /var/log/mumble-webui
chown www-data:mumble-web /var/log/mumble-webui
chmod 775 /var/log/mumble-webui

# Get SSL certificate and set permissions
echo "Getting SSL certificate..."
certbot --nginx -d nimmerchat.xyz --non-interactive --agree-tos --email admin@nimmerchat.xyz

if [ -d "/etc/letsencrypt/live/nimmerchat.xyz" ]; then
    echo "Setting SSL certificate permissions..."
    
    # Fix directory permissions
    find /etc/letsencrypt -type d -exec chmod 755 {} \;
    find /etc/letsencrypt -type f -exec chmod 644 {} \;
    
    # Set group ownership
    chown -R root:ssl-cert /etc/letsencrypt/live
    chown -R root:ssl-cert /etc/letsencrypt/archive
    
    # Set ACLs for www-data
    setfacl -R -m u:www-data:rx /etc/letsencrypt/live
    setfacl -R -m u:www-data:rx /etc/letsencrypt/archive
    
    # Ensure private keys are protected
    find /etc/letsencrypt -name "privkey*.pem" -exec chmod 640 {} \;
    find /etc/letsencrypt -name "privkey*.pem" -exec chown root:ssl-cert {} \;
    
    echo "SSL certificate permissions set"
else
    echo "Warning: SSL certificate directory not found!"
    echo "Please check if certbot created the certificates correctly."
fi

# Reload systemd and start services
systemctl daemon-reload
systemctl enable mumble-webui
systemctl restart mumble-webui
systemctl restart nginx

echo "Deployment complete!"
echo "Your WebUI is now available at https://nimmerchat.xyz"
echo "Check service status with: systemctl status mumble-webui"
echo "View logs with: journalctl -u mumble-webui -f"

# Final checks
echo -n "Checking Nginx status: "
systemctl is-active nginx
echo -n "Checking WebUI status: "
systemctl is-active mumble-webui
echo -n "Checking SSL certificate: "
[ -f "/etc/letsencrypt/live/nimmerchat.xyz/fullchain.pem" ] && echo "OK" || echo "Missing!"
echo -n "Checking www-data groups: "
groups www-data
echo -n "Checking SSL certificate permissions: "
ls -l /etc/letsencrypt/live/nimmerchat.xyz/fullchain.pem