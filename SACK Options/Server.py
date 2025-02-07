#!/usr/bin/env python3
import logging
from scapy.all import *
import sys
import struct
from datetime import datetime

# Define constant marker (4 bytes)
MARKER = 0xDEADBEEF

def setup_logging():
    """
    Setup logging to display debug information both on the console and in the file server_debug.log.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("server_debug.log", mode='w', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

# Dictionary to store received chunks; key is the TCP sequence number
received_chunks = {}

def process_packet(packet):
    logging.debug("Packet received: %s", packet.summary())
    if TCP in packet and packet[TCP].options:
        for opt in packet[TCP].options:
            logging.debug("TCP option: %s", opt)
            # Check for SACK option (either by numeric ID 5 or by name 'SAck')
            if isinstance(opt, tuple) and (opt[0] == 5 or opt[0] == 'SAck'):
                data = opt[1]
                # Case where the data is in bytes (our standard choice)
                if isinstance(data, bytes):
                    if len(data) != 8:
                        logging.warning("Received SACK option with unexpected data length: %d bytes", len(data))
                        continue
                    marker = struct.unpack(">I", data[:4])[0]
                    if marker != MARKER:
                        logging.warning("Invalid marker received: 0x%X (expected 0x%X). Ignoring packet.", marker, MARKER)
                        continue
                    file_chunk = data[4:8]
                # In case the data is received as a tuple (possibly in some interpretations)
                elif isinstance(data, tuple):
                    if len(data) != 2:
                        logging.warning("Received SACK option tuple of unexpected length: %s", data)
                        continue
                    marker, file_data_int = data
                    if marker != MARKER:
                        logging.warning("Invalid marker received in tuple: 0x%X (expected 0x%X). Ignoring packet.", marker, MARKER)
                        continue
                    file_chunk = struct.pack(">I", file_data_int)
                else:
                    logging.warning("Unexpected data format in SACK option: %s", data)
                    continue

                # Use TCP sequence number as key for ordering chunks
                tcp_seq = packet[TCP].seq
                received_chunks[tcp_seq] = file_chunk
                logging.debug("Received chunk from TCP seq %d: Marker=0x%X, Data (hex) = %s", tcp_seq, marker, file_chunk.hex())

def main():
    setup_logging()
    logging.debug("Server started.")

    try:
        listen_port = int(input("Enter the server listening port: ").strip())
    except ValueError:
        logging.error("Invalid port!")
        sys.exit(1)
    
    file_name = input("Enter the file name for saving the received file (leave blank to use default): ").strip()
    if file_name == "":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"file_{timestamp}"
    
    file_path = f"/opt/{file_name}" if not file_name.startswith("/") else file_name
    logging.debug("File will be saved to: %s", file_path)
    logging.info("Listening on port %d...", listen_port)
    
    # Listen to TCP traffic on the specified port for 60 seconds (change timeout if necessary)
    sniff(filter=f"tcp port {listen_port}", prn=process_packet, timeout=60)
    logging.debug("Sniffing finished. Total received chunks: %d", len(received_chunks))
    
    if received_chunks:
        # Reassemble file by sorting chunks based on TCP sequence number
        file_data = b''.join(received_chunks[seq] for seq in sorted(received_chunks))
        logging.debug("Reassembled file data (hex): %s", file_data.hex())
        try:
            with open(file_path, "wb") as f:
                f.write(file_data)
            logging.info("File reassembled and saved to '%s'", file_path)
        except Exception as e:
            logging.error("Error saving file: %s", e)
    else:
        logging.warning("No data received.")

if __name__ == "__main__":
    main()
