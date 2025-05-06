#!/usr/bin/env python3
"""
Geneve Tunnel Troubleshooting Script

This script helps diagnose issues with creating Geneve tunnels by:
1. Checking kernel support for Geneve tunnels
2. Looking for existing Geneve tunnels that might be causing conflicts
3. Verifying network connectivity to the target IP
4. Trying alternative methods for testing Geneve support
"""

import subprocess
import sys
import socket
import random
import time

# Target IP from the error message
TARGET_IP = "145.40.90.203"
UDP_PORT = 6081
VNI = 3762

def run_cmd(cmd, check=False, capture_output=True, text=True, timeout=None):
    """Run a shell command and return the result"""
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed with return code {e.returncode}")
        if hasattr(e, 'stdout') and e.stdout:
            print(f"stdout: {e.stdout}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"stderr: {e.stderr}")
        return e

def check_geneve_kernel_support():
    """Check if the kernel supports Geneve tunnels"""
    print("\n=== Checking Geneve Kernel Support ===")
    
    # Check if the geneve module is loaded
    modules = run_cmd(['lsmod']).stdout
    if 'geneve' in modules:
        print("✅ Geneve module is already loaded")
    else:
        print("Geneve module not loaded, attempting to load it...")
        result = run_cmd(['modprobe', 'geneve'])
        
        if result.returncode == 0:
            print("✅ Successfully loaded Geneve module")
        else:
            print("❌ Failed to load Geneve module")
            print("Troubleshooting:")
            print("  - Your kernel may not have Geneve support")
            print("  - Try installing the required kernel modules")
            print("  - On Ubuntu/Debian: sudo apt-get install linux-modules-extra-$(uname -r)")
            print("  - On CentOS/RHEL: sudo yum install kernel-modules-extra")
    
    # Try to create a test Geneve tunnel to localhost
    print("\nAttempting to create a test Geneve tunnel to localhost...")
    test_tunnel = "geneve_test_local"
    
    # First, make sure the test tunnel doesn't already exist
    run_cmd(['ip', 'link', 'del', test_tunnel], check=False)
    
    result = run_cmd(['ip', 'link', 'add', test_tunnel, 'type', 'geneve', 'id', '1', 
                     'remote', '127.0.0.1', 'dstport', '6081'])
    
    if result.returncode == 0:
        print("✅ Successfully created test Geneve tunnel to localhost")
        run_cmd(['ip', 'link', 'del', test_tunnel], check=False)
        return True
    else:
        print("❌ Failed to create test Geneve tunnel to localhost")
        print("Troubleshooting:")
        print("  - Your kernel may not support Geneve tunnels")
        print("  - You may need to install a newer kernel or compile with Geneve support")
        return False

def check_existing_tunnels():
    """Check for existing Geneve tunnels that might be causing conflicts"""
    print("\n=== Checking for Existing Geneve Tunnels ===")
    
    tunnels = run_cmd(['ip', 'link', 'show']).stdout
    found_geneve = False
    
    print("Existing interfaces:")
    for line in tunnels.splitlines():
        if "geneve" in line.lower():
            found_geneve = True
            tunnel_name = line.split(':')[1].strip()
            print(f"Found Geneve tunnel: {tunnel_name}")
            
            # Get detailed info about this tunnel
            tunnel_info = run_cmd(['ip', '-d', 'link', 'show', 'dev', tunnel_name]).stdout
            print(f"Tunnel details: {tunnel_info.strip()}")
            
            # Ask if user wants to delete this tunnel
            response = input(f"Do you want to delete the existing tunnel {tunnel_name}? (y/n): ")
            if response.lower() == 'y':
                result = run_cmd(['ip', 'link', 'del', tunnel_name])
                if result.returncode == 0:
                    print(f"✅ Successfully deleted tunnel {tunnel_name}")
                else:
                    print(f"❌ Failed to delete tunnel {tunnel_name}")
    
    if not found_geneve:
        print("No existing Geneve tunnels found")

def check_network_connectivity():
    """Check network connectivity to the target IP"""
    print(f"\n=== Checking Network Connectivity to {TARGET_IP} ===")
    
    # Try to ping the target
    print(f"Pinging {TARGET_IP}...")
    result = run_cmd(['ping', '-c', '3', '-W', '2', TARGET_IP])
    
    if result.returncode == 0:
        print(f"✅ Successfully pinged {TARGET_IP}")
    else:
        print(f"❌ Failed to ping {TARGET_IP}")
        print("Note: This doesn't necessarily mean there's a connectivity issue.")
        print("The target might be configured to not respond to ICMP pings.")
    
    # Check UDP connectivity using netcat
    print(f"\nChecking UDP connectivity to {TARGET_IP}:{UDP_PORT}...")
    try:
        result = run_cmd(['nc', '-vzu', TARGET_IP, str(UDP_PORT), '-w', '5'])
        
        if "open" in result.stderr.lower() or result.returncode == 0:
            print(f"✅ UDP port {UDP_PORT} is open on {TARGET_IP}")
        else:
            print(f"❌ UDP port {UDP_PORT} appears to be closed on {TARGET_IP}")
            print("Troubleshooting:")
            print("  - Check if the target is running")
            print("  - Verify there is no firewall blocking UDP traffic to port 6081")
            print("  - The target may not support Geneve protocol")
    except:
        print(f"❌ Failed to check UDP connectivity (netcat may not be installed)")
        print("Troubleshooting:")
        print("  - Install netcat: sudo apt-get install netcat (Ubuntu/Debian)")
        print("  - Install netcat: sudo yum install nc (CentOS/RHEL)")

def try_create_geneve_tunnel():
    """Try to create a Geneve tunnel to the target IP with detailed error reporting"""
    print(f"\n=== Attempting to Create Geneve Tunnel to {TARGET_IP} ===")
    
    # Get the local IP address
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Using local IP address: {local_ip}")
    except Exception as e:
        print(f"Error determining local IP: {e}")
        local_ip = input("Please enter your local IP address: ")
    
    # Generate a unique tunnel name
    tunnel_name = f"geneve_test_{random.randint(1000, 9999)}"
    
    print(f"Creating Geneve tunnel {tunnel_name} from {local_ip} to {TARGET_IP}:{UDP_PORT} (VNI: {VNI})...")
    
    # Try to create the tunnel with strace to get detailed error information
    print("\nRunning with strace to get detailed error information:")
    strace_result = run_cmd(['strace', '-e', 'trace=network,ioctl', 'ip', 'link', 'add', tunnel_name, 'type', 'geneve', 
                           'id', str(VNI), 'remote', TARGET_IP, 'dstport', str(UDP_PORT)])
    
    # Try to create the tunnel normally
    result = run_cmd(['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 
                     'id', str(VNI), 'remote', TARGET_IP, 'dstport', str(UDP_PORT)])
    
    if result.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel {tunnel_name}")
        
        # Try to bring the tunnel up
        print(f"Bringing up tunnel {tunnel_name}...")
        up_result = run_cmd(['ip', 'link', 'set', 'dev', tunnel_name, 'up'])
        
        if up_result.returncode == 0:
            print(f"✅ Successfully brought up Geneve tunnel {tunnel_name}")
            
            # Get detailed tunnel information
            tunnel_info = run_cmd(['ip', '-d', 'link', 'show', 'dev', tunnel_name]).stdout
            print("\nDetailed tunnel information:")
            print(tunnel_info.strip())
        else:
            print(f"❌ Failed to bring up Geneve tunnel {tunnel_name}")
        
        # Clean up
        print(f"Cleaning up tunnel {tunnel_name}...")
        run_cmd(['ip', 'link', 'del', tunnel_name], check=False)
    else:
        print(f"❌ Failed to create Geneve tunnel {tunnel_name}")
        print("Error details:")
        if hasattr(result, 'stderr') and result.stderr:
            print(result.stderr)
        
        print("\nTroubleshooting based on error:")
        if "file exists" in result.stderr.lower():
            print("  - A tunnel with the same parameters already exists")
            print("  - Try deleting existing tunnels and try again")
        elif "operation not supported" in result.stderr.lower():
            print("  - Your kernel does not support Geneve tunnels")
            print("  - Try loading the Geneve module with 'modprobe geneve'")
            print("  - You may need to install a newer kernel or compile with Geneve support")
        elif "permission denied" in result.stderr.lower():
            print("  - You don't have permission to create network interfaces")
            print("  - Make sure you're running the script as root (sudo)")
        elif "network is unreachable" in result.stderr.lower():
            print("  - Cannot reach the target IP")
            print("  - Check your network connectivity")
        else:
            print("  - Check if your kernel supports Geneve tunnels")
            print("  - Verify you have permission to create network interfaces")
            print("  - Check network connectivity to the target")

def main():
    """Main function to run all the troubleshooting steps"""
    print("=== Geneve Tunnel Troubleshooting ===")
    print(f"Target IP: {TARGET_IP}")
    print(f"UDP Port: {UDP_PORT}")
    print(f"VNI: {VNI}")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        print("Please run again with sudo")
        sys.exit(1)
    
    # Run all the troubleshooting steps
    kernel_support = check_geneve_kernel_support()
    check_existing_tunnels()
    check_network_connectivity()
    
    if kernel_support:
        try_create_geneve_tunnel()
    
    print("\n=== Troubleshooting Summary ===")
    print("If you're still having issues creating Geneve tunnels, consider:")
    print("1. Checking if your kernel supports Geneve tunnels")
    print("2. Verifying network connectivity to the target")
    print("3. Ensuring no firewall is blocking UDP traffic to port 6081")
    print("4. Trying the alternative methods in the nrt.py script:")
    print("   - Scapy-based Geneve test")
    print("   - Basic UDP connectivity test")

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        print("Please run again with sudo")
        sys.exit(1)
    main()
