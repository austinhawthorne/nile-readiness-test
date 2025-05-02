#!/bin/bash
# Script to run TigerVNC server in a separate network namespace
# This allows VNC to operate on end0 while FRR tests run on enxf0a731f41761 in the default namespace

# Configuration
VNC_NS="vnc_ns"           # Namespace for VNC
VNC_IFACE="end0"          # Interface to move to VNC namespace
VNC_IP="10.2.0.199"       # IP address for VNC interface
VNC_NETMASK="24"          # Netmask in CIDR notation
VNC_GATEWAY="10.2.0.1"    # Default gateway for VNC namespace
VNC_PORT="5900"           # VNC port (5900 = display :0)
VNC_GEOMETRY="1024x768"   # Screen resolution

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Check if tigervnc-standalone-server is installed
if ! command -v Xvnc >/dev/null 2>&1; then
    echo "TigerVNC not found. Please install it with:"
    echo "sudo apt update && sudo apt install tigervnc-standalone-server"
    exit 1
fi

# Function to clean up on exit
cleanup() {
    echo "Cleaning up..."
    # Kill VNC server
    if [ -f "/tmp/.X0-lock" ]; then
        kill $(cat /tmp/.X0-lock) 2>/dev/null
    fi
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

# Create a minimal X session
mkdir -p /tmp/.vnc
cat > /tmp/.vnc/xstartup << EOF
#!/bin/sh
xterm &
EOF
chmod +x /tmp/.vnc/xstartup

# Start TigerVNC server in the namespace with minimal options
echo "Starting TigerVNC server in namespace $VNC_NS"

# Create a simple xstartup script
mkdir -p /tmp/.vnc
cat > /tmp/.vnc/xstartup << EOF
#!/bin/sh
xterm &
EOF
chmod +x /tmp/.vnc/xstartup

# Try different approaches to start TigerVNC
echo "Attempting to start TigerVNC with different options..."

# Approach 1: Basic start
echo "Approach 1: Basic start"
ip netns exec $VNC_NS Xvnc :0 -geometry $VNC_GEOMETRY -depth 24 &
VNC_PID=$!
sleep 2

# Check if VNC server is running
if ! ip netns exec $VNC_NS ps -p $VNC_PID > /dev/null; then
  echo "Approach 1 failed, trying approach 2..."
  
  # Approach 2: With explicit interface binding
  echo "Approach 2: With explicit interface binding"
  ip netns exec $VNC_NS Xvnc :0 -geometry $VNC_GEOMETRY -depth 24 -interface $VNC_IP &
  VNC_PID=$!
  sleep 2
  
  # Check if VNC server is running
  if ! ip netns exec $VNC_NS ps -p $VNC_PID > /dev/null; then
    echo "Approach 2 failed, trying approach 3..."
    
    # Approach 3: Using vncserver script if available
    if command -v vncserver >/dev/null 2>&1; then
      echo "Approach 3: Using vncserver script"
      ip netns exec $VNC_NS bash -c "DISPLAY=:0 vncserver -geometry $VNC_GEOMETRY -depth 24"
      sleep 2
    else
      echo "vncserver script not found, cannot try approach 3"
      echo "All approaches failed. Please check your TigerVNC installation."
      exit 1
    fi
  fi
fi

# Start xterm manually
echo "Starting xterm in namespace $VNC_NS"
ip netns exec $VNC_NS bash -c "DISPLAY=:0 xterm &"

# Set up port forwarding from host to namespace
echo "Setting up port forwarding to make VNC accessible from outside the namespace"
iptables -t nat -A PREROUTING -p tcp --dport $VNC_PORT -j DNAT --to-destination $VNC_IP:$VNC_PORT
iptables -t nat -A POSTROUTING -p tcp -d $VNC_IP --dport $VNC_PORT -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Check if VNC server is listening
echo "Checking if VNC server is listening..."
ip netns exec $VNC_NS netstat -tuln | grep 5900 || echo "Warning: VNC server not detected on port 5900"

# Print connection information
echo "VNC server should be running on $VNC_IP:$VNC_PORT"
echo "You can also try connecting to localhost:$VNC_PORT due to port forwarding"

# Wait for VNC server to start
sleep 2

# Register cleanup function to run on script exit
trap cleanup EXIT

# Display connection information
echo ""
echo "TigerVNC server is running in namespace $VNC_NS"
echo "Connect to: $VNC_IP:$VNC_PORT"
echo "Press Ctrl+C to stop and clean up"
echo ""

# Keep the script running to maintain the namespace
while true; do
    sleep 1
done
