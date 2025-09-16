#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// Network protocol headers
typedef struct ethernet_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
} ethernet_header;

typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    u_int   saddr;          // Source address
    u_int   daddr;          // Destination address
} ip_header;

typedef struct tcp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int   seq;            // Sequence number
    u_int   ack;            // Acknowledgement number
    u_char  th_offx2;       // Data offset, rsvd
    u_char  th_flags;       // Control flags
    u_short th_win;         // Window
    u_short th_sum;         // Checksum
    u_short th_urp;         // Urgent pointer
} tcp_header;

// Dataset structure for intrusion detection
typedef struct packet_data {
    time_t timestamp;
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int packet_size;
    int tcp_flags;
    char classification[32];
} packet_data;

// Global variables for dataset collection
packet_data dataset[1000];
int dataset_count = 0;
FILE *output_file = NULL;
time_t last_csv_append = 0;

// Function to convert IP address from network byte order to string
void ip_to_string(u_int ip_addr, char* ip_string) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    strcpy(ip_string, inet_ntoa(addr));
}

// Function to classify traffic patterns (basic heuristics)
void classify_packet(packet_data* pkt) {
    // Basic classification rules for educational purposes
    
    // Common service ports
    if (pkt->dst_port == 80 || pkt->dst_port == 443) {
        strcpy(pkt->classification, "WEB_TRAFFIC");
    }
    else if (pkt->dst_port == 22) {
        strcpy(pkt->classification, "SSH_TRAFFIC");
    }
    else if (pkt->dst_port == 21) {
        strcpy(pkt->classification, "FTP_TRAFFIC");
    }
    else if (pkt->dst_port == 53) {
        strcpy(pkt->classification, "DNS_TRAFFIC");
    }
    // Potential scan indicators
    else if (pkt->dst_port > 1024 && (pkt->tcp_flags & 0x02)) { // SYN flag
        strcpy(pkt->classification, "POTENTIAL_SCAN");
    }
    // High ports might indicate P2P or malware
    else if (pkt->dst_port > 49152) {
        strcpy(pkt->classification, "HIGH_PORT");
    }
    else {
        strcpy(pkt->classification, "OTHER");
    }
}

// Function to convert TCP flags to scanlogd format
void tcp_flags_to_string(int flags, char* flag_str) {
    strcpy(flag_str, "--------");
    if (flags & 0x80) flag_str[0] = 'C'; // CWR
    if (flags & 0x40) flag_str[1] = 'E'; // ECE
    if (flags & 0x20) flag_str[2] = 'U'; // URG
    if (flags & 0x10) flag_str[3] = 'A'; // ACK
    if (flags & 0x08) flag_str[4] = 'P'; // PSH
    if (flags & 0x04) flag_str[5] = 'R'; // RST
    if (flags & 0x02) flag_str[6] = 'S'; // SYN
    if (flags & 0x01) flag_str[7] = 'F'; // FIN
}

// Function to initialize CSV file with header only
void initialize_csv_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        printf("Error: Cannot create CSV file %s\n", filename);
        return;
    }

    // Write CSV header matching scanlogd output format
    fprintf(file, "timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str\n");
    fclose(file);
    printf("CSV file initialized: %s\n", filename);
}

// Function to append new data to existing CSV file
void append_dataset_csv(const char* filename, int start_index) {
    if (start_index >= dataset_count) {
        return; // No new data to append
    }

    FILE* file = fopen(filename, "a");  // Append mode
    if (!file) {
        printf("Error: Cannot open CSV file for appending\n");
        return;
    }

    // Write new data rows in scanlogd format (no header)
    for (int i = start_index; i < dataset_count; i++) {
        char tcp_flags_str[9];
        tcp_flags_to_string(dataset[i].tcp_flags, tcp_flags_str);

        struct tm *timeinfo = localtime(&dataset[i].timestamp);
        char time_str[16];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

        fprintf(file, "%ld,\"%s:%d\",\"%s\",\"%d\",\"%s\",\"00\",\"64\",\"%s\"\n",
                dataset[i].timestamp,
                dataset[i].src_ip, dataset[i].src_port,
                dataset[i].dst_ip,
                dataset[i].dst_port,
                tcp_flags_str,
                time_str);
    }

    fclose(file);
    printf("Appended %d new records to %s\n", dataset_count - start_index, filename);
}

// Function to save complete dataset to CSV file (scanlogd format)
void save_dataset_csv(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        printf("Error: Cannot create dataset file\n");
        return;
    }

    // Write CSV header matching scanlogd output format
    fprintf(file, "timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str\n");

    // Write data rows in scanlogd format
    for (int i = 0; i < dataset_count; i++) {
        char tcp_flags_str[9];
        tcp_flags_to_string(dataset[i].tcp_flags, tcp_flags_str);

        struct tm *timeinfo = localtime(&dataset[i].timestamp);
        char time_str[16];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

        fprintf(file, "%ld,\"%s:%d\",\"%s\",\"%d\",\"%s\",\"00\",\"64\",\"%s\"\n",
                dataset[i].timestamp,
                dataset[i].src_ip, dataset[i].src_port,
                dataset[i].dst_ip,
                dataset[i].dst_port,
                tcp_flags_str,
                time_str);
    }

    fclose(file);
    printf("Dataset saved to %s (%d records)\n", filename, dataset_count);
}

// Function to load and display basic packet statistics
void analyze_dataset() {
    int tcp_count = 0, udp_count = 0, other_count = 0;
    
    for (int i = 0; i < dataset_count; i++) {
        if (dataset[i].protocol == 6) tcp_count++;
        else if (dataset[i].protocol == 17) udp_count++;
        else other_count++;
    }
    
    printf("\n=== PACKET STATISTICS ===\n");
    printf("Total packets captured: %d\n", dataset_count);
    printf("TCP packets: %d (%.1f%%)\n", tcp_count, (float)tcp_count/dataset_count*100);
    printf("UDP packets: %d (%.1f%%)\n", udp_count, (float)udp_count/dataset_count*100);
    printf("Other packets: %d (%.1f%%)\n", other_count, (float)other_count/dataset_count*100);
}

// Signal handler for graceful exit
void signal_handler(int signum) {
    printf("\nReceived signal %d, exiting...\n", signum);
    if (dataset_count > 0) {
        // Append any remaining data that wasn't appended during capture
        append_dataset_csv("network_traffic_dataset.csv", 0);
        analyze_dataset();
    }
    exit(0);
}

// Enhanced packet handler with protocol analysis
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int last_appended_count = 0; // Track how many records were last appended

    if (dataset_count >= 1000) return; // Limit dataset size

    ethernet_header *eth_header = (ethernet_header*)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth_header->type) == 0x0800) { // IPv4
        ip_header *ip_hdr = (ip_header*)(packet + 14); // Skip ethernet header
        
        // Initialize packet data structure
        packet_data *pkt = &dataset[dataset_count];
        pkt->timestamp = time(NULL);
        pkt->protocol = ip_hdr->proto;
        pkt->packet_size = pkthdr->len;
        pkt->tcp_flags = 0;
        
        // Convert IP addresses
        ip_to_string(ip_hdr->saddr, pkt->src_ip);
        ip_to_string(ip_hdr->daddr, pkt->dst_ip);
        
        // Analyze TCP packets
        if (ip_hdr->proto == 6) { // TCP
            int ip_header_len = (ip_hdr->ver_ihl & 0x0f) * 4;
            tcp_header *tcp_hdr = (tcp_header*)(packet + 14 + ip_header_len);
            
            pkt->src_port = ntohs(tcp_hdr->sport);
            pkt->dst_port = ntohs(tcp_hdr->dport);
            pkt->tcp_flags = tcp_hdr->th_flags;
        }
        else if (ip_hdr->proto == 17) { // UDP
            // For UDP, we'll extract ports similarly
            int ip_header_len = (ip_hdr->ver_ihl & 0x0f) * 4;
            u_short *udp_ports = (u_short*)(packet + 14 + ip_header_len);
            pkt->src_port = ntohs(udp_ports[0]);
            pkt->dst_port = ntohs(udp_ports[1]);
        }
        
        // Classify the packet (keeping for internal use)
        classify_packet(pkt);
        
        // Display packet information (scanlogd-style format)
        char tcp_flags_str[9];
        tcp_flags_to_string(pkt->tcp_flags, tcp_flags_str);
        
        struct tm *timeinfo = localtime(&pkt->timestamp);
        char time_str[16];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
        
        // Format similar to scanlogd output
        printf("%s:%d to %s ports %d, %s, TOS %02x, TTL %d @%s\n",
               pkt->src_ip, pkt->src_port,
               pkt->dst_ip, pkt->dst_port,
               tcp_flags_str,
               ip_hdr->tos,
               ip_hdr->ttl,
               time_str);

        dataset_count++;

        // Check if we should append to CSV (every 2 seconds)
        time_t current_time = time(NULL);
        if (current_time - last_csv_append >= 2 && dataset_count > last_appended_count) {
            append_dataset_csv("network_traffic_dataset.csv", last_appended_count);
            last_appended_count = dataset_count;
            last_csv_append = current_time;
        }
    }
}

// Function to demonstrate reading from a pcap file
void analyze_pcap_file(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    printf("\n=== ANALYZING PCAP FILE: %s ===\n", filename);
    
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        printf("Error opening pcap file: %s\n", errbuf);
        return;
    }
    
    // Reset dataset for file analysis
    dataset_count = 0;
    
    // Process all packets in the file
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        printf("Error reading pcap file: %s\n", pcap_geterr(handle));
    }
    
    pcap_close(handle);
    
    // Analyze results
    analyze_dataset();
}

int main(int argc, char *argv[]) {
    printf("Network Security - Packet Analysis Tutorial\n");
    printf("===========================================\n\n");

    // Set up signal handler for graceful exit
    signal(SIGINT, signal_handler);

    // Check if user wants to analyze a pcap file from command line
    if (argc > 1) {
        initialize_csv_file("analysis_results.csv");
        analyze_pcap_file(argv[1]);
        save_dataset_csv("analysis_results.csv");
        return 0;
    }

    // Interactive mode - request user input
    int choice;
    char pcap_filename[256];
    int interface_choice = 0;

    printf("Choose analysis mode:\n");
    printf("1. Live packet capture\n");
    printf("2. Analyze PCAP file\n");
    printf("Enter choice (1 or 2): ");

    while (scanf("%d", &choice) != 1 || (choice != 1 && choice != 2)) {
        printf("Invalid choice. Please enter 1 for live capture or 2 for PCAP analysis: ");
        // Clear input buffer
        while (getchar() != '\n');
    }

    if (choice == 2) {
        // PCAP file analysis mode
        printf("Enter PCAP filename: ");
        scanf("%255s", pcap_filename);  // Limit to prevent buffer overflow
        initialize_csv_file("analysis_results.csv");
        analyze_pcap_file(pcap_filename);
        save_dataset_csv("analysis_results.csv");
        return 0;
    }

    // Live capture mode - find and list available devices
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    pcap_if_t *device_list[20];  // Store up to 20 devices for selection

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // List available devices
    printf("\nAvailable network interfaces:\n");
    for (device = alldevs; device != NULL && i < 20; device = device->next) {
        device_list[i] = device;
        printf("%d. %s", i + 1, device->name);
        if (device->description) {
            printf(" (%s)", device->description);
        }
        printf("\n");
        i++;
    }

    if (i == 0) {
        printf("No devices found. Make sure Npcap is installed.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Request interface selection
    printf("Enter interface number (1-%d): ", i);
    while (scanf("%d", &interface_choice) != 1 ||
           interface_choice < 1 || interface_choice > i) {
        printf("Invalid interface number. Please enter a number between 1 and %d: ", i);
        while (getchar() != '\n');
    }

    // Use selected device
    device = device_list[interface_choice - 1];
    printf("\nUsing interface: %s\n", device->name);

    // Initialize CSV file with header before starting capture
    initialize_csv_file("network_traffic_dataset.csv");
    last_csv_append = time(NULL); // Initialize the append timer

    // Open device for live capture
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("\n=== LIVE PACKET CAPTURE ===\n");
    printf("Starting packet capture... Press Ctrl+C to stop.\n\n");

    // Capture packets (unlimited until interrupted)
    if (pcap_loop(handle, -1, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error during packet capture: %s\n", pcap_geterr(handle));
    }

    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    // Analyze captured data
    analyze_dataset();

    // Save dataset for further analysis
    save_dataset_csv("network_traffic_dataset.csv");

    printf("\nTutorial completed. Check the CSV file for dataset analysis.\n");
    printf("\nUsage: %s [pcap_file] - to analyze existing pcap files\n", argv[0]);

    return 0;
}