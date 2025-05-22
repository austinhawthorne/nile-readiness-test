#!/usr/bin/env bash
set -euo pipefail

# Remove any existing aliases for apt and apt-get (ignore errors)
unalias apt >/dev/null 2>&1 || true
unalias apt-get >/dev/null 2>&1 || true

# Install pip
sudo apt install -y pip

# Install Scapy for Python 3
sudo apt install -y python3-scapy

# Install the dhcppython module via pip3
sudo pip3 install dhcppython

# Update package lists and install additional tools
sudo apt update
sudo apt install -y frr freeradius dnsutils ntpdate curl netcat-openbsd openssl

# Set nrt.py to be an executable
sudo chmod +x nrt.py

# Clear screen
clear

echo "All done! 
Now you can run nrt by issuing the following command:  
sudo ./nrt.py  
Set the management interface to Wlan0 and the test interface to eth0.  
Plug the WAN interface of the Firewalla into your router/firewall."
