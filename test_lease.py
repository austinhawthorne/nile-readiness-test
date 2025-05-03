#!/usr/bin/env python3
"""
Test script to examine the structure of the lease object returned by dhcppython
"""

import dhcppython.client as dhcp_client
import dhcppython.options as dhcp_options
import dhcppython.utils as dhcp_utils
import socket
import pprint

def main():
    # Parameters
    iface = "en0"  # Change this to your interface
    server = "192.168.1.1"  # Change this to your DHCP server
    helper_ip = "192.168.1.2"  # Change this to your relay agent IP
    
    # Create a random client MAC address
    client_mac = dhcp_utils.random_mac()
    
    print(f"Testing DHCP with dhcppython library")
    
    try:
        # Create DHCP client
        c = dhcp_client.DHCPClient(
            iface,
            send_from_port=67,
            send_to_port=67
        )
        
        # Create a list of DHCP options
        options_list = dhcp_options.OptionList([
            dhcp_options.options.short_value_to_object(60, "dhcp-test"),
            dhcp_options.options.short_value_to_object(12, socket.gethostname()),
            dhcp_options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
        ])
        
        # This will likely fail due to network issues, but we'll catch the exception
        try:
            lease = c.get_lease(
                client_mac,
                broadcast=False,
                options_list=options_list,
                server=server,
                relay=helper_ip
            )
            
            # Examine the lease object
            print("\nLease object attributes:")
            print(f"dir(lease): {dir(lease)}")
            print("\nLease object representation:")
            print(f"repr(lease): {repr(lease)}")
            print("\nLease object as string:")
            print(f"str(lease): {str(lease)}")
            
            # Try to access common attributes
            print("\nTrying to access common attributes:")
            try:
                print(f"lease.address: {lease.address}")
            except AttributeError:
                print("lease.address: AttributeError")
            
            try:
                print(f"lease.server_id: {lease.server_id}")
            except AttributeError:
                print("lease.server_id: AttributeError")
            
            try:
                print(f"lease.client_ip: {lease.client_ip}")
            except AttributeError:
                print("lease.client_ip: AttributeError")
            
            # Print the lease as a dictionary if possible
            print("\nLease as dictionary:")
            try:
                print(pprint.pformat(lease.__dict__))
            except AttributeError:
                print("lease.__dict__: AttributeError")
            
        except Exception as e:
            print(f"Error getting lease: {e}")
            # Create a mock lease object for testing
            print("\nCreating a mock Lease object for testing...")
            lease = dhcp_client.Lease(None, None, None)
            print("\nMock Lease object attributes:")
            print(f"dir(lease): {dir(lease)}")
            print("\nMock Lease object representation:")
            print(f"repr(lease): {repr(lease)}")
            print("\nMock Lease object as string:")
            print(f"str(lease): {str(lease)}")
            
            # Print the lease as a dictionary if possible
            print("\nMock Lease as dictionary:")
            try:
                print(pprint.pformat(lease.__dict__))
            except AttributeError:
                print("lease.__dict__: AttributeError")
            
    except Exception as e:
        print(f"Error during DHCP test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
