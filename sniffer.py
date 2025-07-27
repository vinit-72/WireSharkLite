from scapy.all import sniff, IP, TCP, UDP, DNS
import csv
from datetime import datetime

# Store captured packets
log_data = []


def handle_packet(pkt):
    # Store info about each packet
    packet_info = {
        'Time': datetime.now().strftime('%H:%M:%S'),
        'Source IP': pkt[IP].src if IP in pkt else '',
        'Destination IP': pkt[IP].dst if IP in pkt else '',
        'Protocol': pkt[IP].proto if IP in pkt else '',
        'Type': 'Other',
        'Src Port': '-',
        'Dst Port': '-',
        'Info': ''
    }

    if TCP in pkt:
        packet_info['Type'] = 'TCP'
        packet_info['Src Port'] = pkt[TCP].sport
        packet_info['Dst Port'] = pkt[TCP].dport
    elif UDP in pkt:
        packet_info['Type'] = 'UDP'
        packet_info['Src Port'] = pkt[UDP].sport
        packet_info['Dst Port'] = pkt[UDP].dport
    elif DNS in pkt:
        packet_info['Type'] = 'DNS'
        try:
            packet_info['Info'] = f"Query: {pkt[DNS].qd.qname.decode()}"
        except:
            packet_info['Info'] = 'Unknown DNS Query'

    log_data.append(packet_info)
    show_packet(packet_info)


def show_packet(pkt):
    # Print each captured packet in a readable format
    print(f"[{pkt['Time']}] {pkt['Source IP']} -> {pkt['Destination IP']} | "
        f"{pkt['Type']} | {pkt.get('Src Port', '-')}/{pkt.get('Dst Port', '-')} | {pkt.get('Info', '')}")


def save_log(filename="packet_log.csv"):
    if not log_data:
        print("\n[-] No packets to save.")
        return

    # Define CSV columns
    headers = ['Time', 'Source IP', 'Destination IP',
               'Protocol', 'Type', 'Src Port', 'Dst Port', 'Info']
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for pkt in log_data:
            writer.writerow(pkt)

    print(f"\n[+] Saved {len(log_data)} packets to {filename}")


def start_capture(count_input, filter_rule="ip"):
    print("[*] Starting packet capture...\n")
    try:
        if count_input:
            pkt_count = int(count_input)
            sniff(filter=filter_rule, prn=handle_packet, count=pkt_count)
        else:
            sniff(filter=filter_rule, prn=handle_packet)
    except KeyboardInterrupt:
        print("\n[-] Capture stopped by user.")
    finally:
        save_log()


if __name__ == "__main__":
    print("Simple LAN Packet Sniffer (Python + Scapy)")
    print("------------------------------------------")
    try:
        num_packets = input(
            "Enter number of packets to capture (leave empty for infinite): ").strip()
        filter_rule = input(
            "Enter filter (e.g., 'tcp', 'udp', 'ip', 'port 53') [default: ip]: ").strip() or "ip"
        start_capture(num_packets, filter_rule)
    except Exception as e:
        print(f"Something went wrong: {e}")
