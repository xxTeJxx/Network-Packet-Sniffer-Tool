pip install scapy matplotlib
sudo python enhanced_packet_sniffer.py


from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import os

packet_count = defaultdict(int)
traffic_stats = defaultdict(lambda: defaultdict(int))  
log_file = "packet_log.txt"
capture_duration = 30  # In seconds

def packet_analyze(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if protocol == 6:  
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags  
            log_entry = f"TCP Packet - Source: {ip_src}:{src_port}, Destination: {ip_dst}:{dst_port}, Flags: {flags}\n"
        elif protocol == 17: 
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            log_entry = f"UDP Packet - Source: {ip_src}:{src_port}, Destination: {ip_dst}:{dst_port}\n"
        elif protocol == 1:  
            proto = "ICMP"
            log_entry = f"ICMP Packet - Source: {ip_src}, Destination: {ip_dst}\n"
        else:
            proto = "Other"
            log_entry = f"Other Packet - Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}\n"
        
        with open(log_file, "a") as log:
            log.write(log_entry)

        packet_count[proto] += 1
        traffic_stats[ip_src][proto] += 1
        traffic_stats[ip_dst][proto] += 1

def start_sniffing(duration):
    print(f"Starting packet sniffing for {duration} seconds...\n")
    
    sniff(timeout=duration, prn=packet_analyze, store=False)
    
    print("\nPacket sniffing completed. Log saved to 'packet_log.txt'.")

def plot_traffic_stats():
    plt.ion()
    fig, ax = plt.subplots()
    
    while True:
        ax.clear()
        protocols = list(packet_count.keys())
        counts = list(packet_count.values())
        ax.bar(protocols, counts, color='blue')
        ax.set_title("Packets Captured by Protocol")
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Packet Count")
        plt.draw()
        plt.pause(1)
        
        if sum(counts) >= capture_duration * 50:  
            break

def display_packet_statistics():
    print("\nReal-time Packet Count (per protocol):")
    print(packet_count)

    print("\nTraffic stats by IP:")
    for ip, proto_data in traffic_stats.items():
        print(f"IP {ip}:")
        for proto, count in proto_data.items():
            print(f"  - {proto}: {count} packets")

def run_sniffer_with_visualization():
    sniff_thread = threading.Thread(target=start_sniffing, args=(capture_duration,))
    sniff_thread.start()

    plot_thread = threading.Thread(target=plot_traffic_stats)
    plot_thread.start()

    sniff_thread.join()
    plot_thread.join()

    display_packet_statistics()

if __name__ == "__main__":
    if os.path.exists(log_file):
        os.remove(log_file)

    print("Enhanced Packet Sniffer")
    run_sniffer_with_visualization()
