# Network Packet Analyzer

> A Windows-based TCP/UDP packet capture tool using Npcap for network security education and research.

## 🎯 Overview

This program captures and analyzes network packets in real-time, outputting data in CSV format for security research. Features automatic WiFi detection and optimized TCP/UDP monitoring.

## ⚡ Quick Setup

### Prerequisites
- **Windows 10/11** (64-bit)
- **Npcap** installed (download from https://nmap.org/npcap/)
- **Administrator privileges** for live capture

### Installation
```bash
# Install MinGW-w64 compiler
winget install BrechtSanders.WinLibs.POSIX.UCRT --accept-source-agreements

# Verify installation
gcc --version
mingw32-make --version
sc query npcap  # Should show RUNNING
```

### Build & Run
```bash
# Compile the program
mingw32-make all

# Run (use Administrator for live capture)
.\pcap-win.exe
```

## 🎮 Usage Guide

### Input Options

The program provides three capture modes:

1. **Live TCP/UDP Capture** - Real-time network monitoring
2. **PCAP File Analysis** - Process saved packet captures
3. **Custom Packet Testing** - Generate synthetic traffic

### Usage Examples

```bash
# Interactive mode (recommended)
.\pcap-win.exe
# Choose: 1) Live capture  2) PCAP analysis  3) Test packets

# Direct PCAP file analysis
.\pcap-win.exe capture.pcap

# Live capture with automatic WiFi detection
.\pcap-win.exe
# Select option 1 for live TCP/UDP monitoring
```

### ⚠️ Important Notes

- **Administrator Rights Required**: Live capture needs admin privileges
- **WiFi Recommended**: Best results with WiFi interfaces for network-wide monitoring
- **Automatic Detection**: Program automatically finds and uses optimal network interface

## 📊 Output Formats

### Real-time Console Display
```
192.168.1.100:12345 to 10.0.0.1 ports 80, --S-----, TOS 00, TTL 64 @14:23:15
192.168.1.100:12346 to 10.0.0.1 ports 443, ---A----, TOS 00, TTL 64 @14:23:16
```

### CSV Data Files
- **Live Capture**: `network_traffic_dataset.csv`
- **PCAP Analysis**: `analysis_results.csv`
- **Test Packets**: `test_packets.csv`

### CSV Structure
```csv
timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str
1640995200,"192.168.1.100:12345","10.0.0.1","80","--S-----","00","64","14:23:15"
```

### TCP Flags Legend
- **S** = SYN (Connection start)
- **A** = ACK (Acknowledgment)
- **P** = PSH (Push data)
- **R** = RST (Reset connection)
- **F** = FIN (Connection end)
- **U** = URG (Urgent data)
- **E** = ECE (ECN Echo)
- **C** = CWR (Congestion Window Reduced)

## 🔧 Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| **GCC not found** | Install MinGW: `winget install BrechtSanders.WinLibs.POSIX.UCRT --accept-source-agreements` |
| **Npcap error** | Check service: `sc query npcap` (should show RUNNING) |
| **Permission denied** | Run as Administrator |
| **No packets captured** | Check WiFi connection and network activity |
| **Build errors** | Ensure Npcap SDK is installed |

### Quick Verification
```bash
gcc --version                    # Check compiler
mingw32-make --version          # Check build tool
sc query npcap                  # Check Npcap service
```

## 📁 Project Files

```
pcap-win/
├── pcap-win.c              # Main source code
├── pcap-win.exe            # Compiled executable
├── Makefile                # Build configuration
├── network_traffic_dataset.csv  # Live capture output
├── analysis_results.csv    # PCAP analysis output
├── test_packets.csv        # Test packet output
└── README.md               # This guide
```

## ⚖️ Legal & Security

- **Educational Use Only**: Designed for network security learning
- **Responsible Usage**: Only capture traffic on authorized networks
- **Privacy Compliance**: Follow local data protection laws
- **Administrator Rights**: Required for live packet capture

---

*Built with Npcap and MinGW-w64 for Windows network analysis.*
