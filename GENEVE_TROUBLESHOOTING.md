# Geneve Tunnel Troubleshooting Guide

This guide helps troubleshoot the error:
```
Error creating Geneve tunnel: Command '['ip', 'link', 'add', 'geneve_test_2699', 'type', 'geneve', 'id', '3762', 'remote', '145.40.90.203', 'dstport', '6081']' returned non-zero exit status 2.
```

## Quick Solutions

1. **Run the fix script** (recommended):
   ```bash
   sudo ./fix_geneve_tunnel.py
   ```
   This script will automatically try multiple methods to fix the Geneve tunnel creation issue.

2. **Run the detailed troubleshooting script**:
   ```bash
   sudo ./geneve_troubleshoot.py
   ```
   This script provides more detailed diagnostics and interactive options.

3. **Use the improved nrt.py**:
   The nrt.py script has been patched to be more resilient to Geneve tunnel creation failures. It now tries multiple methods to create the tunnel and provides better error handling.

## Common Issues and Solutions

### 1. Kernel Module Not Loaded

**Symptoms**: "Operation not supported" error or module not found

**Solutions**:
- Load the Geneve module: `sudo modprobe geneve`
- Install kernel modules: 
  - Ubuntu/Debian: `sudo apt-get install linux-modules-extra-$(uname -r)`
  - CentOS/RHEL: `sudo yum install kernel-modules-extra`

### 2. Existing Tunnels Causing Conflicts

**Symptoms**: "File exists" error

**Solutions**:
- List existing tunnels: `ip link show | grep geneve`
- Delete conflicting tunnels: `sudo ip link del <tunnel_name>`

### 3. Network Connectivity Issues

**Symptoms**: "Network is unreachable" error

**Solutions**:
- Check connectivity to target: `ping 145.40.90.203`
- Check UDP port: `nc -vzu 145.40.90.203 6081`
- Verify no firewall is blocking UDP traffic to port 6081

### 4. Permission Issues

**Symptoms**: "Permission denied" error

**Solutions**:
- Run commands with sudo
- Check if you have the necessary capabilities

## Alternative Testing Methods

If the kernel tunnel method fails, the nrt.py script will automatically try these alternatives:

1. **Scapy-based Geneve test**: Uses Scapy to send and receive Geneve packets
2. **Basic UDP connectivity test**: Checks if the UDP port is open using netcat

## Detailed Explanation

The error "non-zero exit status 2" from the `ip link add` command can have several causes:

1. **Kernel Support**: Your kernel might not support Geneve tunnels or the module might not be loaded
2. **Existing Tunnels**: There might be an existing tunnel with the same parameters
3. **Network Issues**: There might be network connectivity issues to the target IP
4. **Permission Issues**: You might not have the necessary permissions to create network interfaces

The troubleshooting scripts check for all these issues and try multiple methods to create the tunnel:

1. Standard method
2. With explicit local address
3. With a different VNI (Virtual Network Identifier)
4. With a different port

## For Developers

If you need to modify the nrt.py script further, consider:

1. Adding more fallback methods in the `test_geneve_with_tunnel` function
2. Improving error handling for specific error messages
3. Adding more detailed logging for troubleshooting

## Need More Help?

If the troubleshooting scripts don't resolve your issue, please:

1. Run with debug mode: `sudo ./nrt.py --geneve-test --target 145.40.90.203 --debug`
2. Check your kernel version: `uname -r` (Geneve support requires kernel 3.18+)
3. Verify your network configuration: `ip addr show`
