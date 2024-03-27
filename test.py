# import pyshark
# import geoip2.database

# # Load GeoIP database
# reader = geoip2.database.Reader('GeoLite2-City.mmdb')

# def get_location(ip_address):
#     try:
#         response = reader.city(ip_address)
#         country = response.country.name
#         city = response.city.name
#         return f"{city}, {country}"
#     except Exception as e:
#         print(f"Error retrieving location for {ip_address}: {e}")
#         return "Unknown"

# def packet_handler(packet):
#     # Print basic information about each packet
#     print("Packet Info:")
#     print("Timestamp:", packet.sniff_time)
#     print("Protocol:", packet.transport_layer)
    
#     # Check if the packet is TCP or UDP
#     if packet.transport_layer == "TCP":
#         if hasattr(packet, 'ip') and hasattr(packet.ip, 'src'):
#             print("Source IP:", packet.ip.src, "Location:", get_location(packet.ip.src))
#         else:
#             print("Source IP: N/A")
#         if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
#             print("Destination IP:", packet.ip.dst, "Location:", get_location(packet.ip.dst))
#         else:
#             print("Destination IP: N/A")
#         if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport'):
#             print("Source Port:", packet.tcp.srcport)
#         else:
#             print("Source Port: N/A")
#         if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
#             print("Destination Port:", packet.tcp.dstport)
#         else:
#             print("Destination Port: N/A")
#     elif packet.transport_layer == "UDP":
#         if hasattr(packet, 'ip') and hasattr(packet.ip, 'src'):
#             print("Source IP:", packet.ip.src, "Location:", get_location(packet.ip.src))
#         else:
#             print("Source IP: N/A")
#         if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
#             print("Destination IP:", packet.ip.dst, "Location:", get_location(packet.ip.dst))
#         else:
#             print("Destination IP: N/A")
#         if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport'):
#             print("Source Port:", packet.udp.srcport)
#         else:
#             print("Source Port: N/A")
#         if hasattr(packet, 'udp') and hasattr(packet.udp, 'dstport'):
#             print("Destination Port:", packet.udp.dstport)
#         else:
#             print("Destination Port: N/A")
    
#     # Check if the packet has data
#     try:
#         if hasattr(packet, 'data'):
#             print("Payload:", packet.data.data)
#         else:
#             print("Payload: N/A")
#     except AttributeError:
#         print("Payload: N/A")
    
#     print("xxxxxxxxxxxxxxxxxxxx")

# def main():
#     # Define the network interface to capture packets from
#     interface = 'Wi-Fi'  # Change this to the correct interface name
    
#     # Create a capture object to capture packets from the specified interface
#     capture = pyshark.LiveCapture(interface)
    
#     # Start capturing packets indefinitely and process each packet
#     for packet in capture.sniff_continuously(packet_count=10):
#         packet_handler(packet)

# if __name__ == "__main__":
#     main()


import pyshark
import geoip2.database

# Load GeoIP database
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def get_location(ip_address):
    try:
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        return f"{city}, {country}"
    except geoip2.errors.AddressNotFoundError:
        return "Private IP"
    except Exception as e:
        return f"Error: {e}"

def packet_handler(packet):
    # Print basic information about each packet
    print("Packet Info:")
    print("Timestamp:", packet.sniff_time)
    print("Protocol:", packet.transport_layer)
    
    # Check if the packet is TCP or UDP
    if packet.transport_layer == "TCP":
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'src'):
            print("Source IP:", packet.ip.src, "Location:", get_location(packet.ip.src))
        else:
            print("Source IP: N/A")
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
            print("Destination IP:", packet.ip.dst, "Location:", get_location(packet.ip.dst))
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
            print("Source IP:", packet.ip.src, "Location:", get_location(packet.ip.src))
        else:
            print("Source IP: N/A")
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
            print("Destination IP:", packet.ip.dst, "Location:", get_location(packet.ip.dst))
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
    
    # Additional packet details
    print("Packet Length:", packet.length)
    print("Packet Data:", packet)
    
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