#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h> // For Sleep function
#include <time.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// Network protocol headers
typedef struct ethernet_header
{
    u_char dest[6];
    u_char src[6];
    u_short type;
} ethernet_header;

typedef struct ip_header
{
    u_char ver_ihl;         // Version (4 bits) + Internet header length (4 bits)
    u_char tos;             // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;             // Time to live
    u_char proto;           // Protocol
    u_short crc;            // Header checksum
    u_int saddr;            // Source address
    u_int daddr;            // Destination address
} ip_header;

typedef struct tcp_header
{
    u_short sport;   // Source port
    u_short dport;   // Destination port
    u_int seq;       // Sequence number
    u_int ack;       // Acknowledgement number
    u_char th_offx2; // Data offset, rsvd
    u_char th_flags; // Control flags
    u_short th_win;  // Window
    u_short th_sum;  // Checksum
    u_short th_urp;  // Urgent pointer
} tcp_header;

// Dataset structure for intrusion detection
typedef struct packet_data
{
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
void ip_to_string(u_int ip_addr, char *ip_string)
{
    struct in_addr addr;
    addr.s_addr = ip_addr;
    const char *result = inet_ntoa(addr);
    if (result) {
        strncpy(ip_string, result, 15); // 15 chars max for IPv4 + null terminator
        ip_string[15] = '\0'; // Ensure null termination
    } else {
        strcpy(ip_string, "0.0.0.0"); // Fallback
    }
}

// Function to classify traffic patterns (basic heuristics)
void classify_packet(packet_data *pkt)
{
    // Basic classification rules for educational purposes

    // Common service ports
    if (pkt->dst_port == 80 || pkt->dst_port == 443)
    {
        strcpy(pkt->classification, "WEB_TRAFFIC");
    }
    else if (pkt->dst_port == 22)
    {
        strcpy(pkt->classification, "SSH_TRAFFIC");
    }
    else if (pkt->dst_port == 21)
    {
        strcpy(pkt->classification, "FTP_TRAFFIC");
    }
    else if (pkt->dst_port == 53)
    {
        strcpy(pkt->classification, "DNS_TRAFFIC");
    }
    // Potential scan indicators
    else if (pkt->dst_port > 1024 && (pkt->tcp_flags & 0x02))
    { // SYN flag
        strcpy(pkt->classification, "POTENTIAL_SCAN");
    }
    // High ports might indicate P2P or malware
    else if (pkt->dst_port > 49152)
    {
        strcpy(pkt->classification, "HIGH_PORT");
    }
    else
    {
        strcpy(pkt->classification, "OTHER");
    }
}

// Function to convert TCP flags to scanlogd format
void tcp_flags_to_string(int flags, char *flag_str)
{
    strcpy(flag_str, "--------");
    if (flags & 0x80)
        flag_str[0] = 'C'; // CWR
    if (flags & 0x40)
        flag_str[1] = 'E'; // ECE
    if (flags & 0x20)
        flag_str[2] = 'U'; // URG
    if (flags & 0x10)
        flag_str[3] = 'A'; // ACK
    if (flags & 0x08)
        flag_str[4] = 'P'; // PSH
    if (flags & 0x04)
        flag_str[5] = 'R'; // RST
    if (flags & 0x02)
        flag_str[6] = 'S'; // SYN
    if (flags & 0x01)
        flag_str[7] = 'F'; // FIN
}

// Function to initialize CSV file with header only
void initialize_csv_file(const char *filename)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        printf("Error: Cannot create CSV file '%s': %s\n", filename, strerror(errno));
        return;
    }

    // Write CSV header matching scanlogd output format
    fprintf(file, "timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str\n");
    fclose(file);
    printf("CSV file initialized: %s\n", filename);
}

// Function to append new data to existing CSV file
void append_dataset_csv(const char *filename, int start_index)
{
    if (start_index >= dataset_count || start_index < 0)
    {
        return; // No new data to append or invalid index
    }

    FILE *file = fopen(filename, "a"); // Append mode
    if (!file)
    {
        printf("Error: Cannot open CSV file '%s' for appending: %s\n", filename, strerror(errno));
        return;
    }

    // Write new data rows in scanlogd format (no header)
    for (int i = start_index; i < dataset_count; i++)
    {
        char tcp_flags_str[9];
        tcp_flags_to_string(dataset[i].tcp_flags, tcp_flags_str);

        struct tm *timeinfo = localtime(&dataset[i].timestamp);
        char time_str[16];
        if (timeinfo) {
            strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
        } else {
            strcpy(time_str, "00:00:00"); // Fallback
        }

        fprintf(file, "%lld,\"%s:%d\",\"%s\",\"%d\",\"%s\",\"00\",\"64\",\"%s\"\n",
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
void save_dataset_csv(const char *filename)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        printf("Error: Cannot create dataset file '%s': %s\n", filename, strerror(errno));
        return;
    }

    // Write CSV header matching scanlogd output format
    fprintf(file, "timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str\n");

    // Write data rows in scanlogd format
    for (int i = 0; i < dataset_count; i++)
    {
        char tcp_flags_str[9];
        tcp_flags_to_string(dataset[i].tcp_flags, tcp_flags_str);

        struct tm *timeinfo = localtime(&dataset[i].timestamp);
        char time_str[16];
        if (timeinfo) {
            strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
        } else {
            strcpy(time_str, "00:00:00"); // Fallback
        }

        fprintf(file, "%lld,\"%s:%d\",\"%s\",\"%d\",\"%s\",\"00\",\"64\",\"%s\"\n",
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
void analyze_dataset()
{
    if (dataset_count == 0) {
        printf("\n📊 Packet Statistics:\n");
        printf("No packets captured.\n");
        return;
    }

    int tcp_count = 0, udp_count = 0, other_count = 0;

    for (int i = 0; i < dataset_count; i++)
    {
        if (dataset[i].protocol == 6)
            tcp_count++;
        else if (dataset[i].protocol == 17)
            udp_count++;
        else
            other_count++;
    }

    printf("\n📊 Packet Statistics:\n");
    printf("Total packets captured: %d\n", dataset_count);
    printf("TCP packets: %d (%.1f%%)\n", tcp_count, (float)tcp_count / dataset_count * 100);
    printf("UDP packets: %d (%.1f%%)\n", udp_count, (float)udp_count / dataset_count * 100);
    printf("Other packets: %d (%.1f%%)\n", other_count, (float)other_count / dataset_count * 100);
}

// Function to cleanup resources
void cleanup_resources()
{
    // Close any open file handles
    if (output_file) {
        fclose(output_file);
        output_file = NULL;
    }

    // Any other cleanup would go here
}

// Signal handler for graceful exit
void signal_handler(int signum)
{
    printf("\nReceived signal %d, exiting...\n", signum);
    if (dataset_count > 0)
    {
        // Append any remaining data that wasn't appended during capture
        append_dataset_csv("network_traffic_dataset.csv", 0);
        analyze_dataset();
    }

    cleanup_resources();
    exit(0);
}

// Enhanced packet handler with protocol analysis
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int last_appended_count = 0; // Track how many records were last appended

    if (dataset_count >= 1000)
        return; // Limit dataset size

    // Bounds checking for packet size
    if (pkthdr->len < sizeof(ethernet_header)) {
        return; // Packet too small for Ethernet header
    }

    ethernet_header *eth_header = (ethernet_header *)packet;

    // Check if it's an IP packet
    if (ntohs(eth_header->type) == 0x0800)
    {                                                   // IPv4
        if (pkthdr->len < 14 + sizeof(ip_header)) {
            return; // Packet too small for IP header
        }

        ip_header *ip_hdr = (ip_header *)(packet + 14); // Skip ethernet header

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
        if (ip_hdr->proto == 6)
        { // TCP
            int ip_header_len = (ip_hdr->ver_ihl & 0x0f) * 4;
            if (ip_header_len < 20 || pkthdr->len < 14 + ip_header_len + sizeof(tcp_header)) {
                return; // Invalid IP header length or packet too small for TCP header
            }
            tcp_header *tcp_hdr = (tcp_header *)(packet + 14 + ip_header_len);

            pkt->src_port = ntohs(tcp_hdr->sport);
            pkt->dst_port = ntohs(tcp_hdr->dport);
            pkt->tcp_flags = tcp_hdr->th_flags;
        }
        else if (ip_hdr->proto == 17)
        { // UDP
            // For UDP, we'll extract ports similarly
            int ip_header_len = (ip_hdr->ver_ihl & 0x0f) * 4;
            if (ip_header_len < 20 || pkthdr->len < 14 + ip_header_len + 4) {
                return; // Invalid IP header length or packet too small for UDP ports
            }
            u_short *udp_ports = (u_short *)(packet + 14 + ip_header_len);
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
        if (timeinfo) {
            strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
        } else {
            strcpy(time_str, "00:00:00"); // Fallback
        }

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
        if (current_time - last_csv_append >= 2 && dataset_count > last_appended_count)
        {
            append_dataset_csv("network_traffic_dataset.csv", last_appended_count);
            last_appended_count = dataset_count;
            last_csv_append = current_time;
        }
    }
}

// Function to create and analyze custom test packets
void create_custom_test_packet()
{
    printf("\n🎯 Continuous Test Mode: Generating packets until Ctrl+C\n\n");

    // Reset dataset for test
    dataset_count = 0;

    char src_ip[16], dst_ip[16];
    int src_port, dst_port;

    // Get user input for packet specifications
    printf("Enter source IP address (e.g., 192.168.1.100): ");
    if (scanf("%15s", src_ip) != 1) {
        printf("Error reading source IP.\n");
        return;
    }

    printf("Enter destination IP address (e.g., 10.0.0.1): ");
    if (scanf("%15s", dst_ip) != 1) {
        printf("Error reading destination IP.\n");
        return;
    }

    printf("Enter source port (1-65535, or press Enter for random): ");
    char port_input[256];
    fgets(port_input, sizeof(port_input), stdin);
    port_input[strcspn(port_input, "\n")] = 0; // Remove newline

    if (strlen(port_input) == 0) {
        src_port = 10000 + (rand() % 55535); // Random ephemeral port
        printf("Using random source port: %d\n", src_port);
    } else {
        src_port = atoi(port_input);
        if (src_port < 1 || src_port > 65535) {
            src_port = 10000 + (rand() % 55535);
            printf("Invalid port. Using random source port: %d\n", src_port);
        }
    }

    printf("Enter destination port (1-65535, or press Enter for common service): ");
    fgets(port_input, sizeof(port_input), stdin);
    port_input[strcspn(port_input, "\n")] = 0; // Remove newline

    if (strlen(port_input) == 0) {
        // Use common service ports for testing
        int common_ports[] = {80, 443, 22, 21, 53, 25, 110, 143, 993, 995};
        dst_port = common_ports[rand() % 10];
        printf("Using random common destination port: %d\n", dst_port);
    } else {
        dst_port = atoi(port_input);
        if (dst_port < 1 || dst_port > 65535) {
            dst_port = 80;
            printf("Invalid port. Using destination port: %d\n", dst_port);
        }
    }

    printf("Source: %s:%d → Destination: %s:%d - Press Ctrl+C to stop\n\n", src_ip, src_port, dst_ip, dst_port);

    // Generate synthetic packets continuously
    int packet_count = 0;
    while (dataset_count < 1000)  // Safety limit to prevent infinite memory usage
    {
        packet_data *pkt = &dataset[dataset_count];

        // Set packet data
        pkt->timestamp = time(NULL); // Current time
        pkt->protocol = 6; // TCP
        pkt->packet_size = 100 + (rand() % 900); // Random size 100-1000
        pkt->tcp_flags = 0x02; // SYN flag for most packets

        // Copy IP addresses (safe copy)
        strncpy(pkt->src_ip, src_ip, sizeof(pkt->src_ip) - 1);
        pkt->src_ip[sizeof(pkt->src_ip) - 1] = '\0';

        strncpy(pkt->dst_ip, dst_ip, sizeof(pkt->dst_ip) - 1);
        pkt->dst_ip[sizeof(pkt->dst_ip) - 1] = '\0';

        // Set ports with slight variation for realism
        pkt->src_port = src_port + (packet_count % 100); // Small variation
        pkt->dst_port = dst_port;

        // Vary TCP flags for different packets to simulate realistic traffic
        int flag_variation = packet_count % 5;
        if (flag_variation == 0) pkt->tcp_flags = 0x02; // SYN - new connection
        else if (flag_variation == 1) pkt->tcp_flags = 0x10; // ACK - response
        else if (flag_variation == 2) pkt->tcp_flags = 0x18; // PSH+ACK - data
        else if (flag_variation == 3) pkt->tcp_flags = 0x11; // FIN+ACK - close
        else pkt->tcp_flags = 0x04; // RST - reset

        // Classify the packet
        classify_packet(pkt);

        // Display packet info (similar to live capture)
        char tcp_flags_str[9];
        tcp_flags_to_string(pkt->tcp_flags, tcp_flags_str);

        struct tm *timeinfo = localtime(&pkt->timestamp);
        char time_str[16];
        if (timeinfo) {
            strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
        } else {
            strcpy(time_str, "00:00:00");
        }

        printf("Packet #%d: %s:%d to %s ports %d, %s, TOS %02x, TTL %d @%s\n",
               packet_count + 1,
               pkt->src_ip, pkt->src_port,
               pkt->dst_ip, pkt->dst_port,
               tcp_flags_str,
               rand() % 256, // Random TOS
               64, // Standard TTL
               time_str);

        dataset_count++;
        packet_count++;

        // Add a small delay between packets (100-500ms) for realistic timing
        #ifdef _WIN32
            Sleep(100 + (rand() % 400)); // Windows Sleep in milliseconds
        #else
            usleep((100 + (rand() % 400)) * 1000); // Unix usleep in microseconds
        #endif
    }

    printf("\n✓ Generation stopped: %d packets generated", packet_count);
    if (dataset_count >= 1000) printf(" (safety limit reached)");
    printf("\n\n");

    // Analyze the generated test data
    analyze_dataset();

    // Save to CSV for further analysis
    initialize_csv_file("test_packets.csv");
    save_dataset_csv("test_packets.csv");
    printf("Test data saved to 'test_packets.csv'\n");
}

// Function to demonstrate reading from a pcap file
void analyze_pcap_file(const char *filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    printf("\n🎯 Analyzing PCAP file: %s\n", filename);

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL)
    {
        printf("Error opening pcap file: %s\n", errbuf);
        return;
    }

    // Reset dataset for file analysis
    dataset_count = 0;

    // Process all packets in the file
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0)
    {
        printf("Error reading pcap file: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);

    // Analyze results
    analyze_dataset();
}

int main(int argc, char *argv[])
{
    printf("Packet Analysis - Choose mode: 1)Live TCP/UDP 2)PCAP file 3)Test packets\n");

    // Set up signal handler for graceful exit
    signal(SIGINT, signal_handler);

    // Seed random number generator for test packet generation
    srand((unsigned int)time(NULL));

    // Check if user wants to analyze a pcap file from command line
    if (argc > 1)
    {
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
    printf("1. Live TCP/UDP capture (WiFi recommended)\n");
    printf("2. Analyze PCAP file\n");
    printf("3. Continuous packet testing\n");
    printf("Enter choice (1, 2, or 3): ");

    while (1) {
        if (scanf("%d", &choice) != 1) {
            printf("Error reading input. Please enter 1, 2, or 3: ");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        if (choice >= 1 && choice <= 3) {
            break;
        }
        printf("Invalid choice. Please enter 1 for live TCP/UDP capture, 2 for PCAP analysis, or 3 for continuous testing: ");
        while (getchar() != '\n'); // Clear input buffer
    }

    if (choice == 2)
    {
        // PCAP file analysis mode
        printf("Enter PCAP filename: ");
        if (scanf("%255s", pcap_filename) != 1) {
            printf("Error reading filename.\n");
            return 1;
        }
        initialize_csv_file("analysis_results.csv");
        analyze_pcap_file(pcap_filename);
        save_dataset_csv("analysis_results.csv");
        return 0;
    }
    else if (choice == 3)
    {
        // Custom packet testing mode
        create_custom_test_packet();
        return 0;
    }

    // Live capture mode - find and prioritize WiFi interfaces for TCP/UDP capture
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    pcap_if_t *device_list[20]; // Store up to 20 devices for selection
    int wifi_interfaces[20]; // Track WiFi interface indices
    int wifi_count = 0;

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Auto-detect and use WiFi interface for TCP/UDP capture
    printf("\n🎯 Auto-detecting WiFi interface for TCP/UDP capture...\n");

    for (device = alldevs; device != NULL && i < 20; device = device->next)
    {
        device_list[i] = device;

        // Check if this is a WiFi interface (comprehensive detection)
        if ((device->description &&
             (strstr(device->description, "Wireless") ||
              strstr(device->description, "Wi-Fi") ||
              strstr(device->description, "WiFi") ||
              strstr(device->description, "802.11") ||
              strstr(device->description, "WLAN") ||
              strstr(device->description, "Wireless LAN"))) ||
            (device->name &&
             (strstr(device->name, "wlan") ||
              strstr(device->name, "wifi") ||
              strstr(device->name, "wireless")))) {
            wifi_interfaces[wifi_count++] = i;
        }
        i++;
    }

    if (i == 0)
    {
        printf("❌ No network devices found. Please ensure Npcap is installed.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Auto-select primary WiFi interface
    if (wifi_count > 0) {
        interface_choice = wifi_interfaces[0] + 1; // Use first WiFi interface
        printf("✅ WiFi interface detected and ready for TCP/UDP capture\n");
    } else {
        printf("⚠️  No WiFi interfaces found. Using primary network interface.\n");
        printf("   Note: Ethernet capture is limited to local traffic only.\n");
        interface_choice = 1; // Fallback to first available interface
    }

    // Use selected device
    device = device_list[interface_choice - 1];
    printf("🎯 Ready: TCP/UDP capture on %s", device->name);
    if (device->description) printf(" (%s)", device->description);
    printf("\n\n");

    // Initialize CSV file with header before starting capture
    initialize_csv_file("network_traffic_dataset.csv");
    last_csv_append = time(NULL); // Initialize the append timer

    // Open device for comprehensive TCP/UDP capture
    // Parameters: device, snaplen, promiscuous mode, timeout, error buffer
    handle = pcap_open_live(device->name, 65536, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("📡 Starting TCP/UDP capture (promiscuous mode) - Press Ctrl+C to stop\n\n");

    // Set filter to capture only TCP and UDP packets for comprehensive monitoring
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp"; // Capture only TCP and UDP packets

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        // Continue without filter if compilation fails
        printf("⚠️  Filter compilation failed, capturing all packets.\n");
    } else {
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            // Continue without filter if installation fails
            printf("⚠️  Filter installation failed, capturing all packets.\n");
        } else {
            printf("✓ Packet filter applied: '%s'\n", filter_exp);
        }
        pcap_freecode(&fp);
    }
    printf("\n");

    // Capture packets (unlimited until interrupted)
    if (pcap_loop(handle, -1, packet_handler, NULL) < 0)
    {
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

    cleanup_resources();
    return 0;
}