from scapy.all import sniff, IP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Packet captured: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

def start_sniffer(target_ip=None):
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    
    # Define a filter for the sniff function if a target IP is specified
    filter_str = f"ip host {target_ip}" if target_ip else None
    
    # Start sniffing packets, calling packet_callback for each packet
    sniff(prn=packet_callback, filter=filter_str, store=0)

if __name__ == "__main__":
    # Replace '192.168.192.168.76.54' with the desired IP address to filter
    target_ip = '192.168.192.168.76.54'  # Change this to the IP address you want to filter
    start_sniffer(target_ip)