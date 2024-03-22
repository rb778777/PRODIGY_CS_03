import scapy.all as scapy

def sniff_packets(interface, count):
    print(f"\n[*] Sniffing {count} packets on interface {interface}...\n")
    scapy.sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            payload = str(packet[scapy.TCP].payload)
            print(f"Protocol: TCP\t Source IP: {source_ip}\t Destination IP: {dest_ip}\nPayload: {payload}\n")
        elif packet.haslayer(scapy.UDP):
            payload = str(packet[scapy.UDP].payload)
            print(f"Protocol: UDP\t Source IP: {source_ip}\t Destination IP: {dest_ip}\nPayload: {payload}\n")
        elif packet.haslayer(scapy.ICMP):
            payload = str(packet[scapy.ICMP].payload)
            print(f"Protocol: ICMP\t Source IP: {source_ip}\t Destination IP: {dest_ip}\nPayload: {payload}\n")

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")
    count = int(input("Enter the number of packets to sniff: "))
    sniff_packets(interface, count)

if __name__ == "__main__":
    main()

