#!/bin/bash
# Script to run RealVNC server in a separate network namespace
# This allows VNC to operate on end0 while FRR tests run on enxf0a731f41761 in the default namespace

# Configuration
VNC_NS="vnc_ns"           # Namespace for VNC
VNC_IFACE="end0"          # Interface to move to VNC namespace
VNC_IP="10.2.0.199"    # IP address for VNC interface
VNC_NETMASK="24"          # Netmask in CIDR notation
VNC_GATEWAY="10.2.0.1" # Default gateway for VNC namespace

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Function to clean up on exit
cleanup() {
    echo "Cleaning up..."
    # Move interface back to default namespace
    ip netns exec $VNC_NS ip link set $VNC_IFACE netns 1
    # Delete the namespace
    ip netns delete $VNC_NS
    echo "Cleanup complete"
}

# Create the VNC namespace
echo "Creating VNC namespace: $VNC_NS"
ip netns add $VNC_NS

# Set up loopback interface in the namespace
ip netns exec $VNC_NS ip link set lo up

# Move the VNC interface to the namespace
echo "Moving interface $VNC_IFACE to namespace $VNC_NS"
ip link set $VNC_IFACE netns $VNC_NS

# Configure the interface in the namespace
echo "Configuring $VNC_IFACE in namespace $VNC_NS"
ip netns exec $VNC_NS ip addr flush dev $VNC_IFACE
ip netns exec $VNC_NS ip addr add $VNC_IP/$VNC_NETMASK dev $VNC_IFACE
ip netns exec $VNC_NS ip link set dev $VNC_IFACE up

# Add default route in the namespace
echo "Adding default route in namespace $VNC_NS"
ip netns exec $VNC_NS ip route add default via $VNC_GATEWAY

# Set up DNS in the namespace
echo "Setting up DNS in namespace $VNC_NS"
mkdir -p /etc/netns/$VNC_NS
cat > /etc/netns/$VNC_NS/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

# Start RealVNC server in the namespace
echo "Starting RealVNC server in namespace $VNC_NS"
ip netns exec $VNC_NS vncserver

# Register cleanup function to run on script exit
trap cleanup EXIT

# Keep the script running to maintain the namespace
echo "VNC server is running in namespace $VNC_NS"
echo "Press Ctrl+C to stop and clean up"
while true; do
    sleep 1
done
