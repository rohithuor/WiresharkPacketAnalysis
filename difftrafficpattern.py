import pyshark
import time

def main(interface):
    capture = pyshark.LiveCapture(interface)
    for packet in capture.sniff_continuously(packet_count=10):
        print(packet)
        time.sleep(1)  # Simulate steady traffic

if __name__ == "__main__":
    main("Wi-Fi")  # Change interface name as needed
