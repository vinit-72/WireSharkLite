from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP
import csv
from datetime import datetime

# List to store captured packet info
log_data = []

def handle_packet(pkt):
    # Dictionary to hold packet details
    packet_info = {
        'Time': datetime.now().strftime('%H:%M:%S'),
        'Source IP': '',
        'Destination IP': '',
        'Protocol': '',
        'Type': '',
        'Src Port': '-',
        'Dst Port': '-',
        'Info': ''
    }

    # Only handle IPv4 packets
    if IP in pkt:
        packet_info['Source IP'] = pkt[IP].src
        packet_info['Destination IP'] = pkt[IP].dst
        packet_info['Protocol'] = pkt[IP].proto

        if TCP in pkt:
            packet_info['Type'] = 'TCP'
            packet_info['Src Port'] = pkt[TCP].sport
            packet_info['Dst Port'] = pkt[TCP].dport
        elif UDP in pkt:
            packet_info['Type'] = 'UDP'
            packet_info['Src Port'] = pkt[UDP].sport
            packet_info['Dst Port'] = pkt[UDP].dport
        elif ICMP in pkt:
            packet_info['Type'] = 'ICMP'
            packet_info['Info'] = f"Type={pkt[ICMP].type}, Code={pkt[ICMP].code}"
        elif DNS in pkt:
            packet_info['Type'] = 'DNS'
            try:
                packet_info['Info'] = f"Query: {pkt[DNS].qd.qname.decode()}"
            except:
                packet_info['Info'] = 'Unknown DNS Query'
        else:
            # Unknown IPv4 payload → skip
            return
    else:
        # Skip packets without IPv4
        return

    log_data.append(packet_info)
    show_packet(packet_info)

def show_packet(pkt):
    print(f"[{pkt['Time']}] {pkt['Source IP']} -> {pkt['Destination IP']} | "
        f"{pkt['Type']} | {pkt.get('Src Port', '-')}/{pkt.get('Dst Port', '-')} | {pkt.get('Info', '')}")

def save_log(filename="packet_log.csv"):
    if not log_data:
        print("\n[-] No packets to save.")
        return

    headers = ['Time', 'Source IP', 'Destination IP', 'Protocol', 'Type', 'Src Port', 'Dst Port', 'Info']
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for pkt in log_data:
            writer.writerow(pkt)

    print(f"\n[+] Saved {len(log_data)} packets to {filename}")

def start_capture(count_input, filter_rule=None):
    print("[*] Starting packet capture\n")
    try:
        if count_input:
            pkt_count = int(count_input)
            if filter_rule:
                sniff(filter=filter_rule, prn=handle_packet, count=pkt_count)
            else:
                sniff(prn=handle_packet, count=pkt_count)
        else:
            if filter_rule:
                sniff(filter=filter_rule, prn=handle_packet)
            else:
                sniff(prn=handle_packet)
    except KeyboardInterrupt:
        print("\n[-] Capture stopped by user.")
    finally:
        save_log()

if __name__ == "__main__":
    try:
        num_packets = input("Enter number of packets to capture: ").strip()
        filter_rule = input("Enter filter (e.g., 'tcp', 'udp', 'icmp', 'port 53'): ").strip() or None
        start_capture(num_packets, filter_rule)
    except Exception as e:
        print(f"Something went wrong: {e}")
