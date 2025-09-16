# Simplified Port Scan Detector

## Educational Version for Network Security

This is a simplified, educational version of [scanlogd](http://www.openwall.com/scanlogd/) designed to teach the core concepts of network-based intrusion detection systems (NIDS).

## What is Port Scanning?

Port scanning is a reconnaissance technique used by attackers to discover open ports and services on target systems. By systematically attempting to connect to different ports, attackers can:

- Identify running services
- Determine the operating system
- Find potential vulnerabilities
- Plan targeted attacks

## How This Program Works

### 1. Packet Capture

- Uses **libpcap** to capture live network traffic
- Filters for TCP packets only
- Monitors network interface in promiscuous mode

### 2. State Tracking

- Maintains a **hash table** of source IP addresses
- Tracks ports accessed by each IP
- Uses **weighted scoring** system:
  - Privileged ports (< 1024): weight = 3
  - Regular ports (≥ 1024): weight = 1

### 3. Detection Algorithm

```
For each TCP packet:
    - Extract source IP and destination port
    - Skip ACK packets (likely responses)
    - Find/create host entry in hash table
    - Check if port already seen
    - Add port weight to total
    - If total weight ≥ threshold → ALERT!
```

### 4. Threshold-Based Detection

- **Weight Threshold**: 21 (7 privileged ports × 3)
- **Time Window**: 3 seconds between accesses
- **Maximum Hosts**: 256 concurrent tracking

## Building and Running

### Prerequisites

- **libpcap** library (packet capture)
- **GCC** compiler
- **Root privileges** (for packet capture)

### Installation on macOS

```bash
# Install libpcap (if not already installed)
brew install libpcap

# Build the program
make

# Run with root privileges
sudo ./scanlogd-simple [interface]
```

### Example Usage

```bash
# Monitor default interface
sudo ./scanlogd-simple

# Monitor specific interface (e.g., Wi-Fi)
sudo ./scanlogd-simple en0

# Monitor Ethernet
sudo ./scanlogd-simple en1
```

## Testing the Detector

### Generate Test Traffic

Use **nmap** to simulate port scanning:

```bash
# Quick port scan (will trigger alert)
nmap -p 1-100 localhost

# SYN scan
nmap -sS -p 1-50 localhost

# Full TCP connect scan
nmap -sT -p 1-30 localhost
```

### Expected Output

When a scan is detected:

```
*** PORT SCAN DETECTED ***
Source IP: 127.0.0.1
Time: Mon Sep 16 15:30:45 2025
Ports accessed: 15
Total weight: 21 (threshold: 21)
Duration: 2 seconds
Port list: 22 80 443 21 25 53 ...
TCP flags: SYN
```

## Learning Objectives

### 1. Network Packet Analysis

- Understanding TCP/IP headers
- Packet capture techniques
- Network interface monitoring

### 2. Data Structures

- Hash table implementation
- State management
- Efficient lookups

### 3. Security Concepts

- Intrusion detection principles
- Threshold-based alerting
- False positive/negative considerations

### 4. System Programming

- Signal handling
- Memory management
- Cross-platform considerations

## Code Structure

```
scanlogd-simple.c
├── Configuration constants
├── Data structures (host_entry)
├── Hash table functions
├── Packet processing logic
├── Detection algorithm
└── Main capture loop
```

## Key Differences from Original scanlogd

### Simplified:

- ✅ Single file implementation
- ✅ Console output (not syslog)
- ✅ No daemonization
- ✅ No user privilege dropping
- ✅ No chroot jail
- ✅ Basic error handling

### Educational Features:

- 📚 Detailed comments explaining concepts
- 📚 Step-by-step algorithm walkthrough
- 📚 Simple data structures
- 📚 Easy to modify and experiment with

### Removed Complexity:

- ❌ Advanced TCP flag analysis
- ❌ TOS/TTL tracking
- ❌ Flood protection
- ❌ Multiple capture interfaces
- ❌ Configuration files

## Limitations

1. **Memory Bound**: Limited to 256 concurrent hosts
2. **No Persistence**: State lost on restart
3. **Basic Detection**: May have false positives/negatives
4. **Single Interface**: Monitors one interface at a time

## Extensions for Students

Try modifying the code to:

- Add JSON output format
- Implement different detection algorithms
- Add IP whitelisting
- Track connection success/failure
- Add graphical interface
- Support multiple interfaces
- Implement persistent storage

## Further Reading

- [Original scanlogd](http://www.openwall.com/scanlogd/)
- [libpcap documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)
- [Network Security Essentials](https://www.pearson.com/us/higher-education/program/Stallings-Network-Security-Essentials-6th-Edition/PGM332505.html)

## License

Educational use only. Based on the BSD-licensed scanlogd by Solar Designer.
