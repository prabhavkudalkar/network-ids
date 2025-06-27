from collections import defaultdict
import time

# Track IP ↔ MAC mappings
ip_mac_table = defaultdict(set)
mac_ip_table = defaultdict(set)
last_seen = {}

TIME_WINDOW = 30  # seconds

def detect_arp_spoof(packet):
    from scapy.all import ARP

    if ARP in packet and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        current_time = time.time()

        # Update tracking
        ip_mac_table[src_ip].add(src_mac)
        mac_ip_table[src_mac].add(src_ip)
        last_seen[(src_ip, src_mac)] = current_time

        # Keep only recent entries
        for key in list(last_seen):
            if current_time - last_seen[key] > TIME_WINDOW:
                ip, mac = key
                ip_mac_table[ip].discard(mac)
                mac_ip_table[mac].discard(ip)
                if not ip_mac_table[ip]:
                    del ip_mac_table[ip]
                if not mac_ip_table[mac]:
                    del mac_ip_table[mac]
                del last_seen[key]

        # Detection logic
        if len(ip_mac_table[src_ip]) > 1 or len(mac_ip_table[src_mac]) > 3:
            return True, src_ip, list(ip_mac_table[src_ip])

    return False, None, None
