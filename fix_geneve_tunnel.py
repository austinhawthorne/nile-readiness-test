#!/usr/bin/env python3
"""
Fix Geneve Tunnel Creation Error

This script specifically addresses the error:
"Error creating Geneve tunnel: Command '['ip', 'link', 'add', 'geneve_test_2699', 'type', 'geneve', 'id', '3762', 'remote', '145.40.90.203', 'dstport', '6081']' returned non-zero exit status 2."

It attempts to fix the issue by:
1. Checking for and removing any conflicting tunnels
2. Verifying kernel module support
3. Trying alternative tunnel creation methods
"""

import subprocess
import sys
import os
import random
import socket

# Constants from the error message
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

def ensure_geneve_module():
    """Ensure the Geneve kernel module is loaded"""
    print("\n=== Ensuring Geneve Kernel Module is Loaded ===")
    
    # Check if the geneve module is loaded
    modules = run_cmd(['lsmod']).stdout
    if 'geneve' in modules:
        print("✅ Geneve module is already loaded")
        return True
    
    # Try to load the module
    print("Attempting to load Geneve module...")
    result = run_cmd(['modprobe', 'geneve'])
    
    if result.returncode == 0:
        print("✅ Successfully loaded Geneve module")
        return True
    else:
        print("❌ Failed to load Geneve module")
        print("Attempting to install necessary kernel modules...")
        
        # Try to determine the distribution
        if os.path.exists('/etc/debian_version'):
            # Debian/Ubuntu
            kernel_version = run_cmd(['uname', '-r']).stdout.strip()
            install_cmd = ['apt-get', 'update', '&&', 'apt-get', 'install', '-y', f'linux-modules-extra-{kernel_version}']
            print(f"Running: {' '.join(install_cmd)}")
            os.system(' '.join(install_cmd))
        elif os.path.exists('/etc/redhat-release'):
            # CentOS/RHEL
            install_cmd = ['yum', 'install', '-y', 'kernel-modules-extra']
            print(f"Running: {' '.join(install_cmd)}")
            os.system(' '.join(install_cmd))
        else:
            print("Unable to determine distribution for automatic module installation")
            print("Please manually install the Geneve kernel module for your distribution")
            return False
        
        # Try loading the module again
        print("Attempting to load Geneve module again...")
        result = run_cmd(['modprobe', 'geneve'])
        
        if result.returncode == 0:
            print("✅ Successfully loaded Geneve module after installation")
            return True
        else:
            print("❌ Failed to load Geneve module after installation")
            print("Your kernel may not support Geneve tunnels")
            print("You may need to upgrade your kernel or compile with Geneve support")
            return False

def clean_existing_tunnels():
    """Remove any existing Geneve tunnels that might conflict"""
    print("\n=== Cleaning Existing Geneve Tunnels ===")
    
    # Get list of all network interfaces
    tunnels = run_cmd(['ip', 'link', 'show']).stdout
    found_geneve = False
    
    # Look for Geneve tunnels
    for line in tunnels.splitlines():
        if "geneve" in line.lower():
            found_geneve = True
            tunnel_name = line.split(':')[1].strip()
            print(f"Found Geneve tunnel: {tunnel_name}")
            
            # Get detailed info about this tunnel
            tunnel_info = run_cmd(['ip', '-d', 'link', 'show', 'dev', tunnel_name]).stdout
            print(f"Tunnel details: {tunnel_info.strip()}")
            
            # Delete the tunnel
            print(f"Deleting tunnel {tunnel_name}...")
            result = run_cmd(['ip', 'link', 'del', tunnel_name])
            
            if result.returncode == 0:
                print(f"✅ Successfully deleted tunnel {tunnel_name}")
            else:
                print(f"❌ Failed to delete tunnel {tunnel_name}")
    
    if not found_geneve:
        print("No existing Geneve tunnels found")
    
    return not found_geneve

def try_alternative_tunnel_creation():
    """Try alternative methods to create the Geneve tunnel"""
    print("\n=== Trying Alternative Tunnel Creation Methods ===")
    
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
    
    # Method 1: Try with explicit local address
    print("\nMethod 1: Using explicit local address")
    cmd1 = ['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 'id', str(VNI), 
           'remote', TARGET_IP, 'local', local_ip, 'dstport', str(UDP_PORT)]
    result1 = run_cmd(cmd1)
    
    if result1.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel with explicit local address")
        run_cmd(['ip', 'link', 'del', tunnel_name], check=False)
        return True
    
    # Method 2: Try with different VNI
    print("\nMethod 2: Using different VNI")
    new_vni = random.randint(1, 16777215)  # Max VNI value
    cmd2 = ['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 'id', str(new_vni), 
           'remote', TARGET_IP, 'dstport', str(UDP_PORT)]
    result2 = run_cmd(cmd2)
    
    if result2.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel with VNI {new_vni}")
        run_cmd(['ip', 'link', 'del', tunnel_name], check=False)
        return True
    
    # Method 3: Try with different port
    print("\nMethod 3: Using different port")
    new_port = random.randint(1024, 65535)
    cmd3 = ['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 'id', str(VNI), 
           'remote', TARGET_IP, 'dstport', str(new_port)]
    result3 = run_cmd(cmd3)
    
    if result3.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel with port {new_port}")
        run_cmd(['ip', 'link', 'del', tunnel_name], check=False)
        return True
    
    # Method 4: Try with localhost as remote
    print("\nMethod 4: Using localhost as remote (to test basic functionality)")
    cmd4 = ['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 'id', str(VNI), 
           'remote', '127.0.0.1', 'dstport', str(UDP_PORT)]
    result4 = run_cmd(cmd4)
    
    if result4.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel to localhost")
        print("This confirms your system can create Geneve tunnels")
        print("The issue may be with connectivity to the target IP or target configuration")
        run_cmd(['ip', 'link', 'del', tunnel_name], check=False)
        return True
    
    print("❌ All alternative tunnel creation methods failed")
    return False

def check_kernel_version():
    """Check if the kernel version supports Geneve tunnels"""
    print("\n=== Checking Kernel Version ===")
    
    kernel_version = run_cmd(['uname', '-r']).stdout.strip()
    print(f"Current kernel version: {kernel_version}")
    
    # Parse the version
    version_parts = kernel_version.split('.')
    if len(version_parts) >= 2:
        major = int(version_parts[0])
        minor = int(version_parts[1])
        
        if major < 3 or (major == 3 and minor < 18):
            print("❌ Geneve support requires kernel version 3.18 or newer")
            print("Your kernel is too old to support Geneve tunnels")
            print("Consider upgrading your kernel")
            return False
        else:
            print("✅ Kernel version should support Geneve tunnels")
            return True
    else:
        print("Unable to parse kernel version")
        return False

def main():
    """Main function to fix Geneve tunnel creation issues"""
    print("=== Geneve Tunnel Creation Fix ===")
    print(f"Target IP: {TARGET_IP}")
    print(f"UDP Port: {UDP_PORT}")
    print(f"VNI: {VNI}")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        print("Please run again with sudo")
        sys.exit(1)
    
    # Check kernel version
    kernel_ok = check_kernel_version()
    if not kernel_ok:
        print("Your kernel may be too old to support Geneve tunnels")
        print("Consider upgrading your kernel")
    
    # Ensure Geneve module is loaded
    module_ok = ensure_geneve_module()
    if not module_ok:
        print("Failed to load Geneve kernel module")
        print("This is required for Geneve tunnel creation")
    
    # Clean existing tunnels
    clean_existing_tunnels()
    
    # Try to create the tunnel with the original parameters
    print("\n=== Attempting Original Tunnel Creation ===")
    tunnel_name = f"geneve_test_{random.randint(1000, 9999)}"
    cmd = ['ip', 'link', 'add', tunnel_name, 'type', 'geneve', 'id', str(VNI), 
          'remote', TARGET_IP, 'dstport', str(UDP_PORT)]
    result = run_cmd(cmd)
    
    if result.returncode == 0:
        print(f"✅ Successfully created Geneve tunnel {tunnel_name}")
        print("The issue has been resolved!")
        
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
        print(f"❌ Failed to create Geneve tunnel with original parameters")
        print("Trying alternative methods...")
        
        # Try alternative methods
        alt_success = try_alternative_tunnel_creation()
        
        if alt_success:
            print("\n=== Success with Alternative Method ===")
            print("You can modify the nrt.py script to use the successful parameters")
        else:
            print("\n=== All Methods Failed ===")
            print("Possible reasons for failure:")
            print("1. Your kernel doesn't support Geneve tunnels")
            print("2. The target IP doesn't support Geneve protocol")
            print("3. There's a network connectivity issue to the target")
            print("4. There's a firewall blocking UDP traffic to port 6081")
            print("\nRecommendations:")
            print("1. Try using the Scapy-based method in nrt.py instead of tunnel creation")
            print("2. Check if the target actually supports Geneve protocol")
            print("3. Verify network connectivity to the target")
            print("4. Consider upgrading your kernel if it's too old")

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        print("Please run again with sudo")
        sys.exit(1)
    main()
