from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Other"

        print(f"IP Source: {ip_src} -> IP Destination: {ip_dst} | Protocol: {protocol_name}")

        if packet.haslayer(TCP):
            print(f"TCP Payload: {packet[TCP].payload}")
        elif packet.haslayer(UDP):
            print(f"UDP Payload: {packet[UDP].payload}")

def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)
