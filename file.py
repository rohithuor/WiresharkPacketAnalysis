import pyshark
import socket

# Path to the PCAPNG file
pcapng_file = 'packets.pcapng'

# Open the PCAPNG file
cap = pyshark.FileCapture(pcapng_file)

# Function to get the website name associated with an IP address
def get_website(ip_address):
    try:
        website = socket.gethostbyaddr(ip_address)[0]
        return website
    except socket.herror:
        return "Unknown"
    except Exception as e:
        return f"Error: {e}"

# Iterate over each packet in the capture
for packet in cap:
    # Print basic packet information
    print("Packet Info:")
    print("Timestamp:", packet.sniff_time)
    print("Protocol:", packet.transport_layer)
    
    # Access specific fields of the packet with potential error handling
    if hasattr(packet, 'ip'):
        print("Source IP:", packet.ip.src)
        print("Destination IP:", packet.ip.dst)
        # Get website name associated with source and destination IP
        print("Source Website:", get_website(packet.ip.src))
        print("Destination Website:", get_website(packet.ip.dst))
    
    if hasattr(packet, 'tcp'):
        print("Source Port:", packet.tcp.srcport)
        print("Destination Port:", packet.tcp.dstport)
    
    # Additional packet details
    print("Packet Length:", packet.length)
    print("Packet Data:", packet)
    
    # Print payload if available
    if hasattr(packet, 'data'):
        print("Payload:", packet.data.data)
    
    print("xxxxxxxxxxxxxxxxxxxx")
