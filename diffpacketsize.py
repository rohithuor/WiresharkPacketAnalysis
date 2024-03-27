import pyshark

def main(interface):
    capture = pyshark.LiveCapture(interface)
    for packet in capture.sniff_continuously(packet_count=10):
        print(len(packet))

if __name__ == "__main__":
    main("Wi-Fi")  # Change interface name as needed
