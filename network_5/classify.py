import sys
from scapy.all import rdpcap
import numpy as np

def analyze_pcap(file_path):

    outgoing_ips = ['15.204.183.156', '148.251.85.195', '162.19.246.47']
    
    packets = rdpcap(file_path)
    bytes_outgoing = 0
    packet_sizes = []

    for packet in packets:
        packet_length = len(packet)
        packet_sizes.append(packet_length)
        if packet.haslayer('IP'):
            if packet['IP'].src in outgoing_ips:
                bytes_outgoing += packet_length

    total_packets = len(packets)
    median_packet_size = np.median(packet_sizes) if packet_sizes else 0

    return total_packets, bytes_outgoing, median_packet_size

def classify_website(total_packets, bytes_outgoing, median_packet_size):

    print(f"total packets: {total_packets}")

    if total_packets < 100:
        return "lynkapp.co"
    else:
        if bytes_outgoing == 0.0:
            if total_packets < 814:
                return "youtube.com"
            else:
                return "reddit.com"
        else:
            if median_packet_size < 1000:
                return "slither.io"
            else:
                if total_packets < 932:
                    return "googlemaps.com"
                else:
                    return "soundcloud.com"

def main():

    print("please enter website key that you want to tes: 'gmap', 'lynk', 'reddit', 'slither', 'soundcloud', or 'youtube'")

    site_key = input("website key: ")
    
    site_map = {
        "gmap": "googlemaps_test.pcap",
        "lynk": "lynkapp_test.pcap",
        "reddit": "reddit_test.pcap",
        "slither": "slitherio_test.pcap",
        "soundcloud": "soundcloud_test.pcap",
        "youtube": "youtube_test.pcap"
    }

    if site_key not in site_map:
        print("invalid key entered, please enter gmap', 'lynk', 'reddit', 'slither', 'soundcloud', or 'youtube'")
        return

    file_path = f"test_data/{site_map[site_key]}"
    total_packets, bytes_outgoing, median_packet_size = analyze_pcap(file_path)
    site = classify_website(total_packets, bytes_outgoing, median_packet_size)
    
    print(f"you entered '{site_key}', so program used '{site_map[site_key]}', and found this file is most likely from {site}.")

if __name__ == "__main__":
    main()
