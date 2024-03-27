import pyshark

def main(interface):
    capture = pyshark.LiveCapture(interface, display_filter='http')
    for packet in capture.sniff_continuously(packet_count=10):
        print(packet)

if __name__ == "__main__":
    main("Wi-Fi")  # Change interface name as needed
