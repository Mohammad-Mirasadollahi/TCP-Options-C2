#!/usr/bin/env python3
from scapy.all import *
import sys
import os

def main():
    # Get target server IP, destination port, and file path from the user
    target_ip = input("Enter the target server IP: ").strip()
    try:
        target_port = int(input("Enter the target server port: ").strip())
    except ValueError:
        print("Invalid port!")
        sys.exit(1)
    file_path = input("Enter the path of the file to send: ").strip()

    # Check if the file exists
    if not os.path.isfile(file_path):
        print("File not found.")
        sys.exit(1)
    
    # Read the file in binary mode
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Define the chunk size (due to TCP Options field limitations)
    chunk_size = 20
    # Split the file into small chunks
    chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
    total_chunks = len(chunks)
    print(f"Number of chunks created: {total_chunks}")

    # --- Send metadata packet ---
    # Use a custom TCP option with code 253 to send the total number of chunks
    metadata_option = (253, total_chunks.to_bytes(4, 'big'))
    ip_layer = IP(dst=target_ip)
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="PA", seq=1000)
    pkt = ip_layer / tcp_layer
    pkt[TCP].options = [metadata_option]
    send(pkt, verbose=False)
    print(f"Sent metadata: total_chunks = {total_chunks}")

    # --- Send each data chunk ---
    for idx, chunk in enumerate(chunks):
        # Use a custom TCP option with code 254:
        # The first byte is the chunk number and the remaining bytes are the chunk data.
        custom_option = (254, bytes([idx]) + chunk)
        
        # Build the IP and TCP layers
        ip_layer = IP(dst=target_ip)
        # Increment sequence number for each packet (optional)
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="PA", seq=1001+idx)
        
        pkt = ip_layer / tcp_layer
        pkt[TCP].options = [custom_option]
        
        # Send the packet
        send(pkt, verbose=False)
        print(f"Chunk {idx} sent.")
    
    print("File transmission complete.")

if __name__ == "__main__":
    main()
