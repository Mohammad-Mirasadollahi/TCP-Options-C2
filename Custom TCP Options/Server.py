#!/usr/bin/env python3
from scapy.all import *
import sys
from datetime import datetime

# Dictionary to store received chunks; key: chunk number, value: chunk data
received_chunks = {}
# Global variable to hold the expected total number of chunks (received from metadata)
expected_total_chunks = None

def process_packet(packet):
    global received_chunks, expected_total_chunks
    if TCP in packet:
        opts = packet[TCP].options
        if opts:
            for opt in opts:
                if isinstance(opt, tuple):
                    # Check for metadata packet with code 253
                    if opt[0] == 253:
                        data = opt[1]
                        if len(data) >= 4:
                            expected_total_chunks = int.from_bytes(data[:4], 'big')
                            print(f"Received metadata: expected_total_chunks = {expected_total_chunks}")
                    # Check for data chunk packet with code 254
                    elif opt[0] == 254:
                        data = opt[1]
                        if len(data) < 1:
                            continue
                        idx = data[0]       # The first byte represents the chunk number
                        chunk = data[1:]    # The rest is the chunk data
                        received_chunks[idx] = chunk
                        print(f"Received chunk {idx}: {chunk}")

def stop_filter(packet):
    global expected_total_chunks, received_chunks
    # If metadata is received and all expected chunks have been collected, stop sniffing
    if expected_total_chunks is not None and len(received_chunks) >= expected_total_chunks:
        return True
    return False

def main():
    global expected_total_chunks, received_chunks
    try:
        listen_port = int(input("Enter the server listening port: ").strip())
    except ValueError:
        print("Invalid port!")
        sys.exit(1)
    
    file_name = input("Enter the file name for saving the received file (leave blank to use default): ").strip()
    if file_name == "":
        # Generate a file name using the current timestamp (up to seconds)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"file_{timestamp}"
    
    # Prepend /opt to the file name if it's not an absolute path
    if not file_name.startswith("/"):
        file_path = f"/opt/{file_name}"
    else:
        file_path = file_name
    
    print(f"Listening on port {listen_port} ...")
    print("Waiting for file transfer...")

    # Use sniff with stop_filter to automatically stop when file transfer is complete
    sniff(filter=f"tcp port {listen_port}", prn=process_packet, stop_filter=stop_filter)
    
    if expected_total_chunks is not None and len(received_chunks) >= expected_total_chunks:
        print("All expected chunks received.")
    else:
        print("Warning: Metadata not received or file transfer incomplete.")

    if received_chunks:
        # Reassemble the file by sorting chunks based on their index
        file_data = b''.join(received_chunks[idx] for idx in sorted(received_chunks))
        try:
            with open(file_path, "wb") as f:
                f.write(file_data)
            print(f"File reassembled and saved to '{file_path}'.")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("No data received.")

if __name__ == "__main__":
    main()
