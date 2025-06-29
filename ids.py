# ids.py
# A simple network sniffer for a Python-based IDS project

from scapy.all import sniff, IP
from datetime import datetime

# List of suspicious IPs to watch for
suspicious_ips = ["192.168.1.249"]

# This function writes alerts to a file
def log_alert(src_ip, dst_ip):
    with open("alerts.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] ALERT: Suspicious IP detected! {src_ip} -> {dst_ip}\n")

# Called every time a packet is captured
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print("[+] Packet captured:")
        print("    Source IP:", src_ip)
        print("    Destination IP:", dst_ip)

        # Check if the source IP is suspicious
        if src_ip in suspicious_ips:
            print("    [!] ALERT: Suspicious IP detected!\n")
            log_alert(src_ip, dst_ip)
    

# Main function to start the IDS
def main():
    print("[*] Starting the simple IDS (press Ctrl+C to stop)...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()