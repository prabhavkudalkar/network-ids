from scapy.all import sniff, IP, TCP, UDP, ARP
import logging
from detectors.port_scan_detector import detect_port_scan
from detectors.arp_spoof_detector import detect_arp_spoof

# Set up logging
logging.basicConfig(
    filename='logs/intrusions.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

def process_packet(packet):
    # Log basic info
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto = ''
        if TCP in packet:
            proto = 'TCP'
        elif UDP in packet:
            proto = 'UDP'
        else:
            proto = ip_layer.proto

        log_msg = f"Packet: {proto} | {src_ip} -> {dst_ip}"
        print(log_msg)
        logging.info(log_msg)

        # Port scan detection
        is_scan, scan_ip, port_count = detect_port_scan(packet)
        if is_scan:
            alert_msg = f"[ALERT] Port scan detected from {scan_ip} on {port_count} ports!"
            print(alert_msg)
            logging.warning(alert_msg)

    # ARP spoof detection
    if ARP in packet:
        is_spoof, suspect_ip, macs = detect_arp_spoof(packet)
        if is_spoof:
            alert_msg = f"[ALERT] ARP spoofing detected for IP {suspect_ip}! Conflicting MACs: {macs}"
            print(alert_msg)
            logging.warning(alert_msg)

def start_sniffing():
    print("Sniffer running... (Press Ctrl+C to stop)")
    sniff(filter="ip or arp", prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
