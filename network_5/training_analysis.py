from scapy.all import rdpcap
import numpy as np
import os
import json

base_folder_path = 'training_data'

websites = ['googlemaps_caps', 'lynkapp_caps', 'reddit_caps', 'slitherio_caps', 'soundcloud_caps', 'youtube_caps']

def analyze_packets(pcap_path):

    packets = rdpcap(pcap_path)
    
    bytes_incoming = 0
    bytes_outgoing = 0
    inter_arrival_times = []
    packet_sizes = []
    last_time = None
    
    # had 3 different guard nodes - these r ips of them
    ip_addresses = ['15.204.183.156', '148.251.85.195', '162.19.246.47']

    for packet in packets:
        packet_length = len(packet)
        packet_sizes.append(packet_length)
    
        if packet.haslayer('IP'):
            if packet['IP'].src in ip_addresses:
                bytes_outgoing += packet_length
            else:
                bytes_incoming += packet_length
    
        if last_time is not None:
            inter_arrival_time = float(packet.time - last_time)
            inter_arrival_times.append(inter_arrival_time)
    
        last_time = packet.time

    
    inter_arrival_times = np.array(inter_arrival_times, dtype=float)
    packet_sizes = np.array(packet_sizes, dtype=int)
    
    results = {
        'File': pcap_path,
        'Total Packets': len(packets),
        'Bytes Outgoing': bytes_outgoing,
        'Bytes Incoming': bytes_incoming,
        'Mean Interpacket Time': np.mean(inter_arrival_times),
        'Median Interpacket Time': np.median(inter_arrival_times),
        'Std Dev Interpacket Time': np.std(inter_arrival_times),
        'Mean Packet Size': np.mean(packet_sizes),
        'Median Packet Size': np.median(packet_sizes),
        'Std Dev Packet Size': np.std(packet_sizes)
    }
    
    return results

def main():

    all_website_stats = []
    
    for website in websites:
        folder_path = os.path.join(base_folder_path, website)
        results = []
        
        for filename in os.listdir(folder_path):
            if filename.endswith('.pcap'):
                pcap_path = os.path.join(folder_path, filename)
                pcap_results = analyze_packets(pcap_path)
                results.append(pcap_results)
        
        json_filename = f'{website}.json'
        json_path = os.path.join(base_folder_path, json_filename)
        with open(json_path, 'w') as jsonfile:
            json.dump(results, jsonfile, indent=4)

        avg_data = {
            'Site': website,
            'Avg. Total Packets': np.mean([res['Total Packets'] for res in results]),
            'Avg. Bytes Outgoing': np.mean([res['Bytes Outgoing'] for res in results]),
            'Avg. Bytes Incoming': np.mean([res['Bytes Incoming'] for res in results]),
            'Avg. Mean Interpacket Time': np.mean([res['Mean Interpacket Time'] for res in results]),
            'Avg. Median Interpacket Time': np.mean([res['Median Interpacket Time'] for res in results]),
            'Avg. Std Dev Interpacket Time': np.mean([res['Std Dev Interpacket Time'] for res in results]),
            'Avg. Mean Packet Size': np.mean([res['Mean Packet Size'] for res in results]),
            'Avg. Median Packet Size': np.mean([res['Median Packet Size'] for res in results]),
            'Avg. Std Dev Packet Size': np.mean([res['Std Dev Packet Size'] for res in results]),
        }

        all_website_stats.append(avg_data)
    
    with open(os.path.join(base_folder_path, 'all_website_caps.json'), 'w') as jsonfile:
        json.dump(all_website_stats, jsonfile, indent=4)

if __name__ == "__main__":
    main()