# TCP Options C2 POC 🚀

This project is a proof-of-concept for covert file transfer and C2 communication using TCP options. Instead of sending data in the traditional payload, the file data is hidden in the TCP SACK option field—making it hard to detect by standard security monitoring tools. 😎


> **Note:** These scripts were developed with the help of ChatGPT.

## Overview 🔍

The idea behind this project is to send file data covertly within TCP packets. The client splits a file into 4-byte chunks, packs each chunk with a unique marker into an 8-byte payload, and sends these chunks using custom TCP packets. Meanwhile, the server listens for TCP packets on a specified port, extracts the data from the SACK options, and reassembles the original file based on the TCP sequence numbers.


## How It Works ⚙️

### 1. Client Script 🖥️
- **User Input:**  
  - Target server IP and port.  
  - File path for the file to be sent.
- **File Preparation:**  
  - Reads the file in binary mode.  
  - Splits the file into 4-byte chunks (padding the last chunk if needed).
- **Initial TCP Handshake:**  
  - Sends a TCP SYN packet with the SAckOK option to indicate SACK support.
- **Data Transmission:**  
  - For each file chunk, constructs an 8-byte payload:
    - 4 bytes: The constant marker (`0xDEADBEEF`).
    - 4 bytes: The file chunk.
  - Embeds this payload in the SACK option (ID 5) of a TCP packet with the PA (Push Acknowledgment) flag.
  - Uses unique TCP sequence numbers so that the server can reassemble the file in the correct order.
- **Logging:**  
  - Generates detailed debug logs (both on the console and in `client_debug.log`).

### 2. Server Script 🖥️
- **User Input:**  
  - Port to listen on.  
  - File name (or a default name with a timestamp) for saving the reassembled file.
- **Packet Sniffing:**  
  - Uses Scapy’s `sniff` function to capture TCP packets on the specified port for a set duration (e.g., 60 seconds).
- **Data Extraction:**  
  - Examines TCP options in captured packets for SACK options.
  - Verifies that the first 4 bytes match the predefined marker (`0xDEADBEEF`).
  - Extracts the next 4 bytes as file data.
  - Stores each file chunk along with its TCP sequence number.
- **File Reassembly:**  
  - Sorts the received chunks by TCP sequence number and concatenates them to reconstruct the original file.
  - Saves the reassembled file locally and logs the process in `server_debug.log`.


## Note: look like a Real Traffic 🔍
A unique 4-byte marker (`0xDEADBEEF`) is used to confirm that the SACK option actually contains our file data.

To make the covert traffic look like standard TCP traffic, you can tweak the marker values. Instead of using the fixed marker `0xDEADBEEF`, you might choose alternative marker values that are common in real-world network communications. For example:
- **Example Marker:** `0x00000000` (often seen as a start-of-sequence indicator in SACK options)
- **Example Marker:** `0x00000010` (which might represent an end-of-sequence number)

Using such markers can help the covert packets blend in with legitimate traffic, making them even harder for security systems to distinguish from normal TCP communications.

```python
# Example: Using Start Sequence Number of a SACK Block as Marker
SACK_start_seq_num = 0x00000000
SACK_end_seq_num = 0x00000010  # Example end sequence number
MARKER = SACK_start_seq_num  # Use start sequence number as marker
```

## Usage ⚡

### Server Side:
- Run the server script.
- Enter the listening port and desired output file name when prompted.
- The server will capture TCP packets for a predefined timeout period (default is 60 seconds).

### Client Side:
- Run the client script.
- Provide the target server’s IP, port, and the file path to be sent.
- The client will send the file in chunks hidden in the SACK options.


## ⚠️ Warning: Lab-Only Use

This proof of concept (POC) is intended for **laboratory and educational purposes only**. The author disclaims any responsibility or liability for the misuse, unintended consequences, or legal ramifications that may arise from the use of this POC in real-world environments. 

By using this code, you acknowledge that it is solely for testing and learning within a controlled, ethical, and legal context. Any unauthorized or malicious use of this POC is strictly prohibited, and users should ensure they comply with all applicable laws and regulations.

Proceed with caution and always obtain explicit consent when testing in network environments.

## Conclusion 🎉

This project is an example of how TCP options can be exploited for covert file transfer and C2 communication. By hiding data in the SACK option with a specific marker, attackers can create a stealthy channel that evades many traditional security measures. It’s a reminder that when analyzing network traffic, one must look beyond just the payload to detect hidden channels.

Happy experimenting, and remember to use these techniques responsibly! 💻✨
