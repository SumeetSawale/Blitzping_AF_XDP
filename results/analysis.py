#!/usr/bin/env python3
# filepath: /home/chirag/Computer_Networks/Blitzping/compare_pcaps.py

import argparse
import dpkt
import datetime
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import os
from tabulate import tabulate

def analyze_pcap(pcap_file):
    """Extract metrics from a pcap file."""
    packets = []
    packet_sizes = []
    protocols = defaultdict(int)
    ip_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            # Process each packet
            for timestamp, buf in pcap:
                packets.append((timestamp, len(buf)))
                packet_sizes.append(len(buf))
                
                # Parse ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        ip_count += 1
                        
                        # Count by protocol
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp_count += 1
                            protocols['TCP'] += 1
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp_count += 1
                            protocols['UDP'] += 1
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            icmp_count += 1
                            protocols['ICMP'] += 1
                        else:
                            other_count += 1
                            protocols['Other'] += 1
                except Exception:
                    continue
    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        return None
    
    # Calculate metrics
    if len(packets) < 2:
        return None
        
    start_time = packets[0][0]
    end_time = packets[-1][0]
    duration = end_time - start_time
    
    # Calculate inter-packet times
    inter_packet_times = []
    for i in range(1, len(packets)):
        inter_packet_times.append(packets[i][0] - packets[i-1][0])
    
    # Calculate throughput
    if duration > 0:
        packets_per_second = len(packets) / duration
        bits_per_second = sum(packet_sizes) * 8 / duration
    else:
        packets_per_second = 0
        bits_per_second = 0
        
    return {
        'packet_count': len(packets),
        'ip_count': ip_count,
        'tcp_count': tcp_count,
        'udp_count': udp_count,
        'icmp_count': icmp_count,
        'other_count': other_count,
        'duration': duration,
        'avg_packet_size': np.mean(packet_sizes) if packet_sizes else 0,
        'min_packet_size': min(packet_sizes) if packet_sizes else 0,
        'max_packet_size': max(packet_sizes) if packet_sizes else 0,
        'std_packet_size': np.std(packet_sizes) if packet_sizes else 0,
        'packets_per_second': packets_per_second,
        'bits_per_second': bits_per_second,
        'Mbps': bits_per_second / 1_000_000,
        'avg_inter_packet_time': np.mean(inter_packet_times) * 1000 if inter_packet_times else 0,  # ms
        'min_inter_packet_time': min(inter_packet_times) * 1000 if inter_packet_times else 0,  # ms
        'max_inter_packet_time': max(inter_packet_times) * 1000 if inter_packet_times else 0,  # ms
        'std_inter_packet_time': np.std(inter_packet_times) * 1000 if inter_packet_times else 0,  # ms
        'protocols': protocols,
        'packet_sizes': packet_sizes,
        'inter_packet_times': inter_packet_times
    }

def human_readable_size(size_bytes):
    """Convert bytes to human readable format."""
    if size_bytes < 1000:
        return f"{size_bytes} B"
    elif size_bytes < 1000**2:
        return f"{size_bytes/1000:.2f} KB"
    elif size_bytes < 1000**3:
        return f"{size_bytes/1000**2:.2f} MB"
    else:
        return f"{size_bytes/1000**3:.2f} GB"

def plot_comparison(metrics1, metrics2, output_dir="./plots"):
    """Create comparison plots for the metrics."""
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Packet Size Distribution
    plt.figure(figsize=(10, 6))
    if metrics1['packet_sizes'] and metrics2['packet_sizes']:
        plt.hist(metrics1['packet_sizes'], alpha=0.5, label='Normal')
        plt.hist(metrics2['packet_sizes'], alpha=0.5, label='Optimized')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.title('Packet Size Distribution Comparison')
        plt.legend()
        plt.savefig(f"{output_dir}/packet_size_distribution.png")
    
    # 2. Inter-packet Time Distribution
    plt.figure(figsize=(10, 6))
    if metrics1['inter_packet_times'] and metrics2['inter_packet_times']:
        plt.hist(np.array(metrics1['inter_packet_times']) * 1000, alpha=0.5, label='Normal', bins=50)
        plt.hist(np.array(metrics2['inter_packet_times']) * 1000, alpha=0.5, label='Optimized', bins=50)
        plt.xlabel('Inter-packet Time (ms)')
        plt.ylabel('Frequency')
        plt.title('Inter-packet Time Distribution Comparison')
        plt.legend()
        plt.savefig(f"{output_dir}/inter_packet_time_distribution.png")
    
    # 3. Protocol Distribution
    plt.figure(figsize=(12, 6))
    protocols = set(list(metrics1['protocols'].keys()) + list(metrics2['protocols'].keys()))
    normal_counts = [metrics1['protocols'].get(p, 0) for p in protocols]
    optimized_counts = [metrics2['protocols'].get(p, 0) for p in protocols]
    
    x = np.arange(len(protocols))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width/2, normal_counts, width, label='Normal')
    ax.bar(x + width/2, optimized_counts, width, label='Optimized')
    
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Count')
    ax.set_title('Protocol Distribution Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(list(protocols))
    ax.legend()
    plt.savefig(f"{output_dir}/protocol_distribution.png")
    
    # 4. Throughput Comparison (bar chart)
    plt.figure(figsize=(10, 6))
    methods = ['Normal', 'Optimized']
    pps = [metrics1['packets_per_second'], metrics2['packets_per_second']]
    mbps = [metrics1['Mbps'], metrics2['Mbps']]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
    
    ax1.bar(methods, pps)
    ax1.set_ylabel('Packets per Second')
    ax1.set_title('Throughput Comparison (Packets)')
    
    ax2.bar(methods, mbps)
    ax2.set_ylabel('Mbps')
    ax2.set_title('Throughput Comparison (Bandwidth)')
    
    plt.tight_layout()
    plt.savefig(f"{output_dir}/throughput_comparison.png")
    
    print(f"Plots saved to {output_dir}")

def print_comparison(normal_metrics, optimized_metrics):
    """Print a side-by-side comparison of metrics."""
    if not normal_metrics or not optimized_metrics:
        print("Cannot compare metrics, one or both analyses failed.")
        return
        
    # Calculate improvement percentages
    if normal_metrics['packets_per_second'] > 0:
        pps_improvement = (optimized_metrics['packets_per_second'] - normal_metrics['packets_per_second']) / normal_metrics['packets_per_second'] * 100
    else:
        pps_improvement = float('inf')
        
    if normal_metrics['Mbps'] > 0:
        mbps_improvement = (optimized_metrics['Mbps'] - normal_metrics['Mbps']) / normal_metrics['Mbps'] * 100
    else:
        mbps_improvement = float('inf')
        
    # Create a comparison table
    comparison_table = [
        ["Metric", "Normal Socket", "AF_XDP Socket", "Improvement"],
        ["Total packets", normal_metrics['packet_count'], optimized_metrics['packet_count'], 
         f"{(optimized_metrics['packet_count']/normal_metrics['packet_count']-1)*100:.2f}%" if normal_metrics['packet_count'] > 0 else "N/A"],
        ["Packets/second", f"{normal_metrics['packets_per_second']:.2f}", f"{optimized_metrics['packets_per_second']:.2f}",
         f"{pps_improvement:.2f}%"],
        ["Throughput (Mbps)", f"{normal_metrics['Mbps']:.2f}", f"{optimized_metrics['Mbps']:.2f}", 
         f"{mbps_improvement:.2f}%"],
        ["Avg packet size", f"{normal_metrics['avg_packet_size']:.2f} bytes", f"{optimized_metrics['avg_packet_size']:.2f} bytes",
         "N/A"],
        ["Avg inter-packet time", f"{normal_metrics['avg_inter_packet_time']:.3f} ms", f"{optimized_metrics['avg_inter_packet_time']:.3f} ms",
         f"{(normal_metrics['avg_inter_packet_time']/optimized_metrics['avg_inter_packet_time']-1)*100:.2f}%" if optimized_metrics['avg_inter_packet_time'] > 0 else "N/A"]
    ]
    
    print("\n== Performance Comparison: Normal Socket vs AF_XDP ==\n")
    print(tabulate(comparison_table, headers="firstrow", tablefmt="grid"))
    
    print("\n== TCP Specific Performance ==\n")
    tcp_table = [
        ["Metric", "Normal Socket", "AF_XDP Socket", "Improvement"],
        ["TCP packets", normal_metrics['tcp_count'], optimized_metrics['tcp_count'],
         f"{(optimized_metrics['tcp_count']/normal_metrics['tcp_count']-1)*100:.2f}%" if normal_metrics['tcp_count'] > 0 else "N/A"],
        ["TCP packets/second", 
         f"{normal_metrics['tcp_count']/normal_metrics['duration']:.2f}" if normal_metrics['duration'] > 0 else "N/A",
         f"{optimized_metrics['tcp_count']/optimized_metrics['duration']:.2f}" if optimized_metrics['duration'] > 0 else "N/A",
         f"{((optimized_metrics['tcp_count']/optimized_metrics['duration'])/(normal_metrics['tcp_count']/normal_metrics['duration'])-1)*100:.2f}%" 
         if normal_metrics['duration'] > 0 and optimized_metrics['duration'] > 0 and normal_metrics['tcp_count'] > 0 else "N/A"]
    ]
    print(tabulate(tcp_table, headers="firstrow", tablefmt="grid"))
    
    print("\n== SUMMARY ==\n")
    if pps_improvement > 0:
        print(f"AF_XDP socket implementation is {pps_improvement:.2f}% faster in packet throughput!")
    else:
        print(f"Normal socket implementation is {-pps_improvement:.2f}% faster in packet throughput!")
    
    if mbps_improvement > 0:
        print(f"AF_XDP socket implementation is {mbps_improvement:.2f}% faster in data throughput!")
    else:
        print(f"Normal socket implementation is {-mbps_improvement:.2f}% faster in data throughput!")

def main():
    parser = argparse.ArgumentParser(description='Compare performance metrics from pcap files.')
    parser.add_argument('normal_pcap', help='Path to normal.pcap file (standard socket implementation)')
    parser.add_argument('optimized_pcap', help='Path to optimized.pcap file (AF_XDP implementation)')
    parser.add_argument('--output-dir', default='./plots', help='Directory to save comparison plots')
    args = parser.parse_args()
    
    print(f"Analyzing {args.normal_pcap}...")
    normal_metrics = analyze_pcap(args.normal_pcap)
    
    print(f"Analyzing {args.optimized_pcap}...")
    optimized_metrics = analyze_pcap(args.optimized_pcap)
    
    print_comparison(normal_metrics, optimized_metrics)
    
    # Generate plots if both analyses were successful
    if normal_metrics and optimized_metrics:
        plot_comparison(normal_metrics, optimized_metrics, args.output_dir)

if __name__ == "__main__":
    main()

