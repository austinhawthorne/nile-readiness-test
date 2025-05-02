#!/bin/bash
# Script to run VNC server in a separate network namespace using macvlan
# This creates a virtual interface linked to the physical interface,
# allowing both the host and the namespace to use the physical interface

# Configuration
VNC_NS="vnc_ns"           # Namespace for VNC
PHYSICAL_IFACE="end0"     # Physical interface to link to
MACVLAN_IFACE="macvlan0"  # Name of the macvlan interface in the namespace
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

# Check if TigerVNC is installed
if ! command -v Xvnc >/dev/null 2>&1; then
    echo "TigerVNC not found. Please install it with:"
    echo "sudo apt update && sudo apt install tigervnc-standalone-server"
    exit 1
fi

# Check if xterm is installed
if ! command -v xterm >/dev/null 2>&1; then
    echo "xterm not found. Please install it with:"
    echo "sudo apt update && sudo apt install xterm"
    exit 1
fi

# Function to clean up on exit
cleanup() {
    echo "Cleaning up..."
    # Kill VNC server
    if [ -f "/tmp/.X0-lock" ]; then
        kill $(cat /tmp/.X0-lock) 2>/dev/null
    fi
    
    # Remove the macvlan interface
    ip link del $MACVLAN_IFACE 2>/dev/null
    
    # Delete the namespace
    ip netns delete $VNC_NS 2>/dev/null
    
    # Remove iptables rules
    iptables -t nat -D PREROUTING -p tcp --dport $VNC_PORT -j DNAT --to-destination $VNC_IP:$VNC_PORT 2>/dev/null
    iptables -t nat -D POSTROUTING -p tcp -d $VNC_IP --dport $VNC_PORT -j MASQUERADE 2>/dev/null
    
    echo "Cleanup complete"
}

# Create the VNC namespace
echo "Creating VNC namespace: $VNC_NS"
ip netns add $VNC_NS

# Set up loopback interface in the namespace
ip netns exec $VNC_NS ip link set lo up

# Create macvlan interface
echo "Creating macvlan interface linked to $PHYSICAL_IFACE"
ip link add $MACVLAN_IFACE link $PHYSICAL_IFACE type macvlan mode bridge
ip link set $MACVLAN_IFACE netns $VNC_NS

# Configure the interface in the namespace
echo "Configuring $MACVLAN_IFACE in namespace $VNC_NS"
ip netns exec $VNC_NS ip addr add $VNC_IP/$VNC_NETMASK dev $MACVLAN_IFACE
ip netns exec $VNC_NS ip link set dev $MACVLAN_IFACE up

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
      cleanup
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

# Test connectivity from namespace to host
echo "Testing connectivity from namespace to host..."
HOST_IP=$(ip -4 addr show $PHYSICAL_IFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$HOST_IP" ]; then
  ip netns exec $VNC_NS ping -c 1 $HOST_IP > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Connectivity test: ${GREEN}Success${RESET}"
  else
    echo "Connectivity test: ${RED}Fail${RESET}"
    echo "Warning: Namespace cannot reach host. This may affect VNC connectivity."
  fi
else
  echo "Could not determine host IP address on $PHYSICAL_IFACE"
fi

# Print connection information
echo ""
echo "VNC server should be running in namespace $VNC_NS"
echo "Connect to: $VNC_IP:$VNC_PORT"
echo "You can also try connecting to localhost:$VNC_PORT due to port forwarding"
echo "Press Ctrl+C to stop and clean up"
echo ""

# Register cleanup function to run on script exit
trap cleanup EXIT

# Keep the script running to maintain the namespace
while true; do
    sleep 1
done
