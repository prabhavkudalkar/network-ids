from collections import defaultdict
import time

# Settings
THRESHOLD = 10         # Number of ports accessed
TIME_WINDOW = 10       # Time window in seconds

# Track connections: {IP: [(timestamp, port), ...]}
connection_history = defaultdict(list)

def detect_port_scan(packet):
    from scapy.all import IP, TCP

    if IP in packet and TCP in packet:
        if packet[TCP].flags == "S":  # SYN packet (start of connection)
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()

            # Add current attempt
            connection_history[src_ip].append((current_time, dst_port))

            # Keep only recent entries
            connection_history[src_ip] = [
                (t, port) for (t, port) in connection_history[src_ip]
                if current_time - t <= TIME_WINDOW
            ]

            # Get unique ports
            unique_ports = set(port for _, port in connection_history[src_ip])

            if len(unique_ports) > THRESHOLD:
                return True, src_ip, len(unique_ports)

    return False, None, None
