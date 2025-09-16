/*
 * Simplified Port Scan Detector - Educational Version
 *
 * This is a simplified version of scanlogd for teaching purposes.
 * It demonstrates the core concepts of network-based intrusion detection:
 * - Packet capture using libpcap
 * - TCP traffic analysis
 * - Hash table-based state tracking
 * - Threshold-based detection
 *
 * Original scanlogd: http://www.openwall.com/scanlogd/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Configuration Parameters */
#define PORT_WEIGHT_PRIVILEGED   3  /* Weight for ports < 1024 */
#define PORT_WEIGHT_REGULAR      1  /* Weight for ports >= 1024 */
#define SCAN_WEIGHT_THRESHOLD    21 /* Minimum weight to trigger alert (7 * 3) */
#define SCAN_DELAY_THRESHOLD     3  /* Max seconds between port accesses */
#define MAX_PORTS_TRACKED        20 /* Max ports to remember per host */
#define HASH_TABLE_SIZE          256 /* Size of hash table */
#define MAX_HOSTS                256 /* Max hosts to track */

/* Data structure for tracking each source IP */
struct host_entry {
    struct in_addr saddr;              /* Source IP address */
    time_t last_seen;                  /* Last packet timestamp */
    time_t first_seen;                 /* First packet timestamp */
    int port_count;                    /* Number of ports accessed */
    int total_weight;                  /* Total weight of ports */
    unsigned short ports[MAX_PORTS_TRACKED]; /* List of ports accessed */
    unsigned char tcp_flags_or;        /* OR of all TCP flags seen */
    unsigned char tcp_flags_and;       /* AND of all TCP flags seen */
};

/* Global state */
static struct host_entry hosts[MAX_HOSTS];
static int active_hosts = 0;

/* Simple hash function for IP addresses */
unsigned int hash_ip(struct in_addr addr) {
    return (addr.s_addr >> 24) ^ (addr.s_addr >> 16) ^
           (addr.s_addr >> 8) ^ addr.s_addr;
}

/* Find or create host entry */
struct host_entry* find_or_create_host(struct in_addr saddr) {
    time_t now = time(NULL);

    /* Look for existing entry */
    for (int i = 0; i < active_hosts; i++) {
        if (hosts[i].saddr.s_addr == saddr.s_addr) {
            return &hosts[i];
        }
    }

    /* Check if entry is too old (simple cleanup) */
    if (active_hosts > 0) {
        int oldest = 0;
        for (int i = 1; i < active_hosts; i++) {
            if (hosts[i].last_seen < hosts[oldest].last_seen) {
                oldest = i;
            }
        }

        /* If oldest entry is older than threshold, reuse it */
        if (now - hosts[oldest].last_seen > SCAN_DELAY_THRESHOLD) {
            hosts[oldest].saddr = saddr;
            hosts[oldest].last_seen = now;
            hosts[oldest].first_seen = now;
            hosts[oldest].port_count = 0;
            hosts[oldest].total_weight = 0;
            memset(hosts[oldest].ports, 0, sizeof(hosts[oldest].ports));
            hosts[oldest].tcp_flags_or = 0;
            hosts[oldest].tcp_flags_and = 0xFF;
            return &hosts[oldest];
        }
    }

    /* Create new entry if we have space */
    if (active_hosts < MAX_HOSTS) {
        hosts[active_hosts].saddr = saddr;
        hosts[active_hosts].last_seen = now;
        hosts[active_hosts].first_seen = now;
        hosts[active_hosts].port_count = 0;
        hosts[active_hosts].total_weight = 0;
        memset(hosts[active_hosts].ports, 0, sizeof(hosts[active_hosts].ports));
        hosts[active_hosts].tcp_flags_or = 0;
        hosts[active_hosts].tcp_flags_and = 0xFF;
        return &hosts[active_hosts++];
    }

    return NULL; /* No space available */
}

/* Check if port was already accessed */
int port_already_seen(struct host_entry* host, unsigned short port) {
    for (int i = 0; i < host->port_count; i++) {
        if (host->ports[i] == port) {
            return 1;
        }
    }
    return 0;
}

/* Log detected port scan */
void log_port_scan(struct host_entry* host) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &host->saddr, src_ip, sizeof(src_ip));

    printf("\n*** PORT SCAN DETECTED ***\n");
    printf("Source IP: %s\n", src_ip);
    printf("Time: %s", ctime(&host->first_seen));
    printf("Ports accessed: %d\n", host->port_count);
    printf("Total weight: %d (threshold: %d)\n", host->total_weight, SCAN_WEIGHT_THRESHOLD);
    printf("Duration: %ld seconds\n", host->last_seen - host->first_seen);

    printf("Port list: ");
    for (int i = 0; i < host->port_count && i < 10; i++) {
        printf("%u ", ntohs(host->ports[i]));
    }
    if (host->port_count > 10) printf("... (%d more)", host->port_count - 10);
    printf("\n");

    /* Decode TCP flags */
    printf("TCP flags: ");
    if (host->tcp_flags_or & 0x01) printf("FIN ");
    if (host->tcp_flags_or & 0x02) printf("SYN ");
    if (host->tcp_flags_or & 0x04) printf("RST ");
    if (host->tcp_flags_or & 0x08) printf("PSH ");
    if (host->tcp_flags_or & 0x10) printf("ACK ");
    if (host->tcp_flags_or & 0x20) printf("URG ");
    printf("\n\n");
}

/* Process a TCP packet */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    struct host_entry *host;
    unsigned short dest_port;
    unsigned char tcp_flags;
    int weight;

    /* Skip Ethernet header (14 bytes) */
    packet += 14;
    ip_header = (struct ip*)packet;

    /* Check if it's TCP */
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    /* Get TCP header */
    tcp_header = (struct tcphdr*)(packet + (ip_header->ip_hl * 4));

    /* Get destination port and TCP flags */
    dest_port = tcp_header->th_dport;
    tcp_flags = tcp_header->th_flags;

    /* Skip ACK packets (likely responses, not scans) */
    if (tcp_flags & TH_ACK) {
        return;
    }

    /* Find or create host entry */
    host = find_or_create_host(ip_header->ip_src);
    if (!host) {
        return; /* No space for new host */
    }

    /* Check if we've seen this port before */
    if (port_already_seen(host, dest_port)) {
        /* Update TCP flags but don't count as new port */
        host->tcp_flags_or |= tcp_flags;
        host->tcp_flags_and &= tcp_flags;
        host->last_seen = time(NULL);
        return;
    }

    /* Update host information */
    host->last_seen = time(NULL);
    host->tcp_flags_or |= tcp_flags;
    host->tcp_flags_and &= tcp_flags;

    /* Calculate port weight */
    weight = (ntohs(dest_port) < 1024) ? PORT_WEIGHT_PRIVILEGED : PORT_WEIGHT_REGULAR;
    host->total_weight += weight;

    /* Add port to list */
    if (host->port_count < MAX_PORTS_TRACKED) {
        host->ports[host->port_count++] = dest_port;
    }

    /* Check if this triggers a scan alert */
    if (host->total_weight >= SCAN_WEIGHT_THRESHOLD) {
        log_port_scan(host);
        /* Reset weight to avoid repeated alerts */
        host->total_weight = 0;
    }
}

/* Signal handler for clean exit */
void signal_handler(int signum) {
    printf("\nReceived signal %d, exiting...\n", signum);
    exit(0);
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter;
    char filter_exp[] = "tcp"; /* Capture only TCP packets */

    printf("Simplified Port Scan Detector\n");
    printf("===========================\n\n");

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Find default device if not specified */
    if (argc > 1) {
        device = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", error_buffer);
            return 1;
        }
        if (alldevs == NULL) {
            fprintf(stderr, "No devices found\n");
            return 1;
        }
        device = alldevs->name;
    }

    printf("Monitoring device: %s\n", device);
    printf("Filter: %s\n\n", filter_exp);

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 1;
    }

    /* Compile and apply filter */
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Bad filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Starting packet capture... Press Ctrl+C to stop.\n\n");

    /* Start capturing packets */
    pcap_loop(handle, 0, process_packet, NULL);

    /* Cleanup */
    pcap_freecode(&filter);
    pcap_close(handle);

    return 0;
}
