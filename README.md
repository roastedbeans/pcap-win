# Network Packet Analyzer - Setup Guide

A Windows-based network packet capture and analysis tool using Npcap library, designed for network security education and research.

## Overview

This program captures network packets and outputs them in scanlogd format for analysis. It can operate in two modes:

- **Live Capture**: Captures packets from network interfaces in real-time
- **File Analysis**: Processes existing PCAP files for offline analysis

## Requirements

### Software Dependencies

- **Windows 10/11** (64-bit recommended)
- **Npcap** (packet capture library)
- **Visual Studio** or **MinGW-w64** compiler
- **Administrator privileges** (required for packet capture)

### Hardware Requirements

- Network interface card
- Minimum 4GB RAM
- 100MB free disk space

## Installation

### 1. Install Npcap

1. Download Npcap from: https://nmap.org/npcap/
2. Run the installer **as Administrator**
3. **Important**: During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
4. Reboot your system after installation

### 2. Install Development Environment

#### Option A: Visual Studio (Recommended)

1. Download Visual Studio Community (free)
2. Install with "Desktop development with C++" workload
3. Ensure Windows 10/11 SDK is included

#### Option B: MinGW-w64

1. Download from: https://www.mingw-w64.org/
2. Add MinGW bin directory to PATH environment variable
3. Verify installation: `gcc --version`

### 3. Download Npcap SDK

1. Download Npcap SDK from: https://nmap.org/npcap/
2. Extract to a folder (e.g., `C:\npcap-sdk`)
3. Note the paths to:
   - Include directory: `C:\npcap-sdk\Include`
   - Lib directory: `C:\npcap-sdk\Lib` or `C:\npcap-sdk\Lib\x64`

## Compilation

### Using Visual Studio

1. Create a new "Empty Project" in Visual Studio
2. Add the source file to your project
3. Configure project properties:
   - **Configuration Properties > C/C++ > General**
     - Additional Include Directories: `C:\npcap-sdk\Include`
   - **Configuration Properties > Linker > General**
     - Additional Library Directories: `C:\npcap-sdk\Lib\x64` (for 64-bit)
   - **Configuration Properties > Linker > Input**
     - Additional Dependencies: Add `wpcap.lib` and `ws2_32.lib`
4. Build the project (Ctrl+Shift+B)

### Using MinGW-w64

```bash
gcc -o packet_analyzer.exe packet_analyzer.c -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib\x64" -lwpcap -lws2_32
```

### Using Command Line (if libraries in system path)

```bash
gcc -o packet_analyzer.exe packet_analyzer.c -lwpcap -lws2_32
```

## Usage

### Administrator Privileges

**Important**: The program must be run as Administrator to access network interfaces.

Right-click on Command Prompt → "Run as administrator"

### Interactive Interface

The program now features an interactive menu for easy operation:

1. **Choose Analysis Mode**: Select between live packet capture or PCAP file analysis
2. **Interface Selection**: For live capture, choose from available network interfaces
3. **File Input**: For PCAP analysis, enter the filename to analyze

### Command Line Usage

You can still bypass the interactive menu by providing a PCAP filename directly:

```bash
# Analyze PCAP file directly (bypasses interactive menu)
packet_analyzer.exe capture.pcap
```

### Live Packet Capture

When choosing live capture mode interactively:

```bash
packet_analyzer.exe
# Then follow the on-screen prompts:
# 1. Choose "1" for live capture
# 2. Select interface number from the list
```

### PCAP File Analysis

When choosing PCAP analysis mode interactively:

```bash
packet_analyzer.exe
# Then follow the on-screen prompts:
# 1. Choose "2" for PCAP analysis
# 2. Enter the PCAP filename when prompted
```

## Output

### Console Output Format (scanlogd-style)

```
192.168.1.100:12345 to 10.0.0.1 ports 80, --A-----, TOS 00, TTL 64 @14:23:15
```

### CSV File Output

- **Live capture**: `network_traffic_dataset.csv`
- **File analysis**: `analysis_results.csv`

**CSV Generation Process:**

1. **Header Creation**: CSV file is initialized with headers before data collection begins
2. **Periodic Append**: During live capture, new packet data is appended to the CSV file every 2 seconds
3. **Final Save**: Complete dataset is saved at the end of capture/analysis

**CSV Format:**

```csv
timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str
1640995200,"192.168.1.100:12345","10.0.0.1","80","--A-----","00","64","14:23:15"
```

## TCP Flags Reference

- **C** = CWR (Congestion Window Reduced)
- **E** = ECE (ECN Echo)
- **U** = URG (Urgent)
- **A** = ACK (Acknowledgment)
- **P** = PSH (Push)
- **R** = RST (Reset)
- **S** = SYN (Synchronize)
- **F** = FIN (Finish)

## Troubleshooting

### Common Issues

#### "Error finding devices"

- **Solution**: Install Npcap with WinPcap API-compatible mode
- Verify Npcap service is running: `sc query npcap`

#### "Could not open device"

- **Solution**: Run program as Administrator
- Check Windows Firewall settings

#### Compilation errors

- **wpcap.lib not found**: Verify Npcap SDK paths in compiler settings
- **pcap.h not found**: Add Npcap Include directory to compiler include paths

#### No packets captured

- Check network activity during capture
- Try different network interface
- Disable antivirus temporarily (may block packet capture)

### Verification Steps

1. **Check Npcap installation**:

   ```cmd
   sc query npcap
   ```

   Should show "RUNNING" status

2. **Verify network interfaces**:

   ```cmd
   ipconfig /all
   ```

   Note active interfaces

3. **Test with Wireshark** (if available):
   - If Wireshark can capture packets, this tool should work too

## Educational Use

This tool is designed for:

- Network security education
- Protocol analysis learning
- Dataset generation for research
- Understanding packet capture fundamentals

## Security Notes

- **Use responsibly**: Only capture traffic on networks you own or have permission to monitor
- **Privacy**: Be aware of data protection laws in your jurisdiction
- **Firewall**: Some security software may flag packet capture as suspicious behavior

## Support

For technical issues:

1. Verify all requirements are met
2. Check Windows Event Viewer for system errors
3. Test with minimal antivirus interference
4. Ensure latest Npcap version is installed

## File Structure

```
project/
├── packet_analyzer.c       # Main source code
├── packet_analyzer.exe     # Compiled executable
├── network_traffic_dataset.csv  # Output (live capture)
├── analysis_results.csv    # Output (file analysis)
└── README.md              # This file
```

---

**Note**: This tool is for educational purposes. Always comply with local laws and network policies when capturing network traffic.
