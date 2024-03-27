import pyshark

def packet_handler(packet):
    # Print basic information about each packet
    print("Packet Info:")
    print("Timestamp:", packet.sniff_time)
    print("Protocol:", packet.transport_layer)
    
    # Check if the packet is TCP or UDP
    if packet.transport_layer == "TCP":
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'src'):
            print("Source IP:", packet.ip.src)
        else:
            print("Source IP: N/A")
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
            print("Destination IP:", packet.ip.dst)
        else:
            print("Destination IP: N/A")
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport'):
            print("Source Port:", packet.tcp.srcport)
        else:
            print("Source Port: N/A")
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
            print("Destination Port:", packet.tcp.dstport)
        else:
            print("Destination Port: N/A")
    elif packet.transport_layer == "UDP":
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'src'):
            print("Source IP:", packet.ip.src)
        else:
            print("Source IP: N/A")
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
            print("Destination IP:", packet.ip.dst)
        else:
            print("Destination IP: N/A")
        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport'):
            print("Source Port:", packet.udp.srcport)
        else:
            print("Source Port: N/A")
        if hasattr(packet, 'udp') and hasattr(packet.udp, 'dstport'):
            print("Destination Port:", packet.udp.dstport)
        else:
            print("Destination Port: N/A")
    
    # Check if the packet has data
    try:
        if hasattr(packet, 'data'):
            print("Payload:", packet.data.data)
        else:
            print("Payload: N/A")
    except AttributeError:
        print("Payload: N/A")
    
    print("xxxxxxxxxxxxxxxxxxxx")

def main():
    # Define the network interface to capture packets from
    interface = 'Wi-Fi'  # Change this to the correct interface name
    
    # Create a capture object to capture packets from the specified interface
    capture = pyshark.LiveCapture(interface)
    
    # Start capturing packets indefinitely and process each packet
    for packet in capture.sniff_continuously(packet_count=10):
        packet_handler(packet)

if __name__ == "__main__":
    main()
