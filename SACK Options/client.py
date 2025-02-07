#!/usr/bin/env python3
import logging
from scapy.all import *
import sys
import os
import struct

# Define constant marker (4 bytes)
MARKER = 0xDEADBEEF

def setup_logging():
    """
    Setup logging to display debug information both on the console and in the client_debug.log file.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("client_debug.log", mode='w', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    setup_logging()
    logging.debug("Client started.")

    # Get input from the user
    target_ip = input("Enter the target server IP: ").strip()
    try:
        target_port = int(input("Enter the target server port: ").strip())
    except ValueError:
        logging.error("Invalid port!")
        sys.exit(1)
    file_path = input("Enter the path of the file to send: ").strip()

    # Check if the file exists
    if not os.path.isfile(file_path):
        logging.error("File not found: %s", file_path)
        sys.exit(1)
    
    # Read file in binary mode
    with open(file_path, "rb") as f:
        file_data = f.read()
    logging.debug("File '%s' read successfully, size: %d bytes.", file_path, len(file_data))

    # Split file into 4-byte chunks (each chunk is sent as data in a SACK option)
    chunk_size = 4
    chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
    total_chunks = len(chunks)
    logging.debug("Total Chunks: %d", total_chunks)

    # --- Send TCP SYN with SAckOK option ---
    ip_layer = IP(dst=target_ip)
    tcp_syn = TCP(sport=RandShort(), dport=target_port, flags="S", seq=1000, options=[('SAckOK', b'')])
    send(ip_layer/tcp_syn, verbose=False)
    logging.debug("Sent TCP SYN with SAckOK option to %s:%d", target_ip, target_port)

    # --- Send data using standard SACK blocks (8 bytes) ---
    for idx, chunk in enumerate(chunks):
        if len(chunk) < chunk_size:
            # If less than 4 bytes, pad with zeros
            chunk = chunk.ljust(chunk_size, b'\x00')
        # Construct an 8-byte payload: 4 bytes marker + 4 bytes data
        payload = struct.pack(">I", MARKER) + chunk
        sack_option = (5, payload)
        tcp_data = TCP(sport=RandShort(), dport=target_port, flags="PA", seq=1001+idx, options=[sack_option])
        pkt = ip_layer / tcp_data
        send(pkt, verbose=False)
        file_data_int = struct.unpack(">I", chunk)[0]
        logging.debug("Sent chunk %d: Marker=0x%X, Data = %d", idx, MARKER, file_data_int)

    logging.info("File transmission complete.")

if __name__ == "__main__":
    main()
