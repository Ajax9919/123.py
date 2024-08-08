import scapy.all as scapy
import time
import matplotlib.pyplot as plt

def packet_handler(packet):
    # Basic packet analysis
    print(packet.summary())

    # Add your custom analysis logic here
    # For example:
    # if packet.haslayer(scapy.IP):
    #     print(f"IP packet from {packet[scapy.IP].src} to {packet[scapy.IP].dst}")

def analyze_traffic(interface, duration):
    packets = scapy.sniff(iface=interface, count=0, timeout=duration)

    # Basic statistics
    print(f"Total packets captured: {len(packets)}")
    print(f"Capture duration: {duration} seconds")

    # Protocol distribution
    protocol_counts = {}
    for packet in packets:
        protocol = str(packet.proto)
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    
    # Plot protocol distribution
    plt.bar(protocol_counts.keys(), protocol_counts.values())
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.title("Protocol Distribution")
    plt.show()

    # Add more analysis based on your requirements

if __name__ == "__main__":
    interface = "your_interface"  # Replace with your interface name
    duration = 10  # Capture duration in seconds
    analyze_traffic(interface, duration)
