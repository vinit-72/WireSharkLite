from scapy.all import sniff, IP, TCP, UDP, DNS
import csv
from datetime import datetime

# List to store captured packet data
packet_log = []

def process_packet(packet):
    data = {}
    if IP in packet:
        data['Time'] = datetime.now().strftime('%H:%M:%S')
        data['Source IP'] = packet[IP].src
        data['Destination IP'] = packet[IP].dst
        data['Protocol'] = packet[IP].proto

        if TCP in packet:
            data['Type'] = 'TCP'
            data['Src Port'] = packet[TCP].sport
            data['Dst Port'] = packet[TCP].dport

        elif UDP in packet:
            data['Type'] = 'UDP'
            data['Src Port'] = packet[UDP].sport
            data['Dst Port'] = packet[UDP].dport

        elif DNS in packet:
            data['Type'] = 'DNS'
            try:
                data['Query'] = str(packet[DNS].qd.qname.decode())
            except:
                data['Query'] = 'Unknown'

        else:
            data['Type'] = 'Other'
            data['Src Port'] = '-'
            data['Dst Port'] = '-'

        packet_log.append(data)
        print_packet(data)

def print_packet(pkt):
    print(f"[{pkt['Time']}] {pkt['Source IP']} -> {pkt['Destination IP']} | {pkt['Type']} | {pkt.get('Src Port', '-')}/{pkt.get('Dst Port', '-')}")

def save_to_csv(filename="packet_log.csv"):
    keys = packet_log[0].keys() if packet_log else []
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for pkt in packet_log:
            writer.writerow(pkt)
    print(f"\n[+] Saved {len(packet_log)} packets to {filename}")

def start_sniffing(packet_count=20, filter_str="ip"):
    print("[*] Starting packet capture...\n")
    sniff(filter=filter_str, prn=process_packet, count=packet_count)
    save_to_csv()

if __name__ == "__main__":
    print("Simple LAN Packet Sniffer (Python + Scapy)")
    print("------------------------------------------")
    try:
        packet_count = int(input("Enter number of packets to capture: "))
        filter_str = input("Enter filter (e.g., 'tcp', 'udp', 'ip', 'port 53'): ").strip() or "ip"
        start_sniffing(packet_count, filter_str)
    except KeyboardInterrupt:
        print("\n[-] Capture interrupted.")
        if packet_log:
            save_to_csv()
