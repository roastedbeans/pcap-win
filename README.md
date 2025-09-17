# Windows Packet Analyzer

Simple network packet capture tool for educational purposes.

## What it does

- Captures TCP/UDP packets from WiFi interface
- Displays packets in real-time
- Saves data to `packets.csv` when stopped with Ctrl+C

## Prerequisites

1. **Npcap** - Download from https://npcap.com/
2. **Visual Studio** or **MinGW**
3. **Administrator privileges**

## Compilation

```cmd
# Visual Studio
cl packet_analyzer.c /link wpcap.lib ws2_32.lib

# MinGW
gcc -o packet_analyzer.exe packet_analyzer.c -lwpcap -lws2_32
```

## Usage

```cmd
# Run as Administrator
packet_analyzer.exe

# Stop with Ctrl+C
```

## Data Structures

### Network Headers

```c
typedef struct ethernet_header {
    u_char dest[6];      // Destination MAC
    u_char src[6];       // Source MAC
    u_short type;        // Protocol type
} ethernet_header;

typedef struct ip_header {
    u_char ver_ihl;      // Version + Header length
    u_char tos;          // Type of service
    u_short tlen;        // Total length
    u_short identification;
    u_short flags_fo;    // Flags + Fragment offset
    u_char ttl;          // Time to live
    u_char proto;        // Protocol (6=TCP, 17=UDP)
    u_short crc;         // Header checksum
    u_int saddr;         // Source IP
    u_int daddr;         // Destination IP
} ip_header;

typedef struct tcp_header {
    u_short sport;       // Source port
    u_short dport;       // Destination port
    u_int seq;           // Sequence number
    u_int ack;           // Acknowledgment number
    u_char th_offx2;     // Data offset
    u_char th_flags;     // Control flags
    u_short th_win;      // Window size
    u_short th_sum;      // Checksum
    u_short th_urp;      // Urgent pointer
} tcp_header;
```

### Packet Storage

```c
typedef struct packet_data {
    time_t timestamp;
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int tcp_flags;
    int tos;
    int ttl;
} packet_data;
```

## Libraries Used

### Standard C

```c
#include <stdio.h>      // File operations, printf
#include <stdlib.h>     // exit
#include <string.h>     // String operations
#include <signal.h>     // Ctrl+C handling
#include <time.h>       // Time functions
```

### Windows

```c
#include <winsock2.h>   // Windows networking
#include <ws2tcpip.h>   // TCP/IP functions
#include <windows.h>    // Windows API
```

### Packet Capture

```c
#include <pcap.h>       // Packet capture library
```

## Key Functions

### Standard C

```c
printf()         // Display output
fopen()          // Open file
fprintf()        // Write to file
fclose()         // Close file
time()           // Get timestamp
localtime()      // Convert time
strftime()       // Format time
strcpy()         // Copy strings
strstr()         // Search strings
signal()         // Set Ctrl+C handler
exit()           // Exit program
```

### Windows

```c
WSAStartup()     // Initialize Windows networking
WSACleanup()     // Cleanup Windows networking
inet_ntoa()      // Convert IP to string
ntohs()          // Convert network to host byte order
```

### PCap Functions

```c
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
// Find all network devices

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
// Open device for live capture

int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
// Compile packet filter

int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
// Apply packet filter

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
// Start packet capture loop

void pcap_close(pcap_t *p);
// Close capture handle

void pcap_freealldevs(pcap_if_t *alldevs);
// Free device list

void pcap_freecode(struct bpf_program *fp);
// Free compiled filter
```

## Output

**Console:**

```
192.168.1.100:52341 to 104.18.19.125 ports 443, ---AP---, TTL 64 @14:30:25
```

**CSV (`packets.csv`):**

```
timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str
1234567890,"192.168.1.100:52341","104.18.19.125","443","---AP---","00","64","14:30:25"
```

## TCP Flags

```
--------
   UAPRSF
U = URG (Urgent)
A = ACK (Acknowledgment)
P = PSH (Push)
R = RST (Reset)
S = SYN (Synchronize)
F = FIN (Finish)
```
