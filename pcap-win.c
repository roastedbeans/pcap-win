/*
 * Simple Packet Analyzer for Windows
 * Captures TCP/UDP packets from WiFi and saves to CSV
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <signal.h>
 #include <pcap.h>
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <windows.h>
 #include <time.h>
 
 #pragma comment(lib, "wpcap.lib")
 #pragma comment(lib, "ws2_32.lib")
 
 // Ethernet header
 typedef struct ethernet_header {
     u_char dest[6];
     u_char src[6];
     u_short type;
 } ethernet_header;
 
 // IP header
 typedef struct ip_header {
     u_char ver_ihl;
     u_char tos;
     u_short tlen;
     u_short identification;
     u_short flags_fo;
     u_char ttl;
     u_char proto;       // 6=TCP, 17=UDP
     u_short crc;
     u_int saddr;        // Source IP
     u_int daddr;        // Destination IP
 } ip_header;
 
 // TCP header
 typedef struct tcp_header {
     u_short sport;      // Source port
     u_short dport;      // Destination port
     u_int seq;
     u_int ack;
     u_char th_offx2;
     u_char th_flags;    // SYN, ACK, FIN, etc.
     u_short th_win;
     u_short th_sum;
     u_short th_urp;
 } tcp_header;
 
 // Packet storage
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
 
 packet_data dataset[10000];
 int packet_count = 0;
 
 // Convert IP number to text
 void ip_to_string(u_int ip_addr, char *ip_string) {
     struct in_addr addr;
     addr.s_addr = ip_addr;
     strcpy(ip_string, inet_ntoa(addr));
 }
 
 // Convert TCP flags to readable format
 void tcp_flags_to_string(int flags, char *flag_str) {
     strcpy(flag_str, "--------");
     if (flags & 0x20) flag_str[2] = 'U'; // URG
     if (flags & 0x10) flag_str[3] = 'A'; // ACK
     if (flags & 0x08) flag_str[4] = 'P'; // PSH
     if (flags & 0x04) flag_str[5] = 'R'; // RST
     if (flags & 0x02) flag_str[6] = 'S'; // SYN
     if (flags & 0x01) flag_str[7] = 'F'; // FIN
 }
 
 // Save packets to CSV file
 void save_to_csv() {
     FILE *file = fopen("packets.csv", "w");
     fprintf(file, "timestamp,source,destination,ports,tcp_flags,tos,ttl,time_str\n");
     
     for (int i = 0; i < packet_count; i++) {
         char tcp_flags_str[9];
         tcp_flags_to_string(dataset[i].tcp_flags, tcp_flags_str);
         
         struct tm *timeinfo = localtime(&dataset[i].timestamp);
         char time_str[16];
         strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
         
         fprintf(file, "%lld,\"%s:%d\",\"%s\",\"%d\",\"%s\",\"%02x\",\"%d\",\"%s\"\n",
                 (long long)dataset[i].timestamp,
                 dataset[i].src_ip, dataset[i].src_port,
                 dataset[i].dst_ip,
                 dataset[i].dst_port,
                 tcp_flags_str,
                 dataset[i].tos,
                 dataset[i].ttl,
                 time_str);
     }
     
     fclose(file);
 }
 
 // Handle Ctrl+C
 void signal_handler(int signum) {
     save_to_csv();
     exit(0);
 }
 
 // Process each captured packet
 void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
     if (packet_count >= 10000) return;
     if (pkthdr->len < 34) return; // Minimum packet size
     
     ethernet_header *eth_header = (ethernet_header *)packet;
     
     // Only process IP packets
     if (ntohs(eth_header->type) == 0x0800) {
         ip_header *ip_hdr = (ip_header *)(packet + 14);
         packet_data *pkt = &dataset[packet_count];
         
         // Extract IP information
         pkt->timestamp = time(NULL);
         ip_to_string(ip_hdr->saddr, pkt->src_ip);
         ip_to_string(ip_hdr->daddr, pkt->dst_ip);
         pkt->protocol = ip_hdr->proto;
         pkt->tcp_flags = 0;
         pkt->src_port = 0;
         pkt->dst_port = 0;
         pkt->tos = ip_hdr->tos;
         pkt->ttl = ip_hdr->ttl;
         
         // Extract port information for TCP/UDP
         if (ip_hdr->proto == 6 || ip_hdr->proto == 17) {
             int ip_header_len = (ip_hdr->ver_ihl & 0x0f) * 4;
             u_short *ports = (u_short *)(packet + 14 + ip_header_len);
             pkt->src_port = ntohs(ports[0]);
             pkt->dst_port = ntohs(ports[1]);
             
             // Get TCP flags
             if (ip_hdr->proto == 6) {
                 tcp_header *tcp_hdr = (tcp_header *)(packet + 14 + ip_header_len);
                 pkt->tcp_flags = tcp_hdr->th_flags;
             }
         }
         
         // Display packet
         char tcp_flags_str[9];
         tcp_flags_to_string(pkt->tcp_flags, tcp_flags_str);
         
         time_t now = time(NULL);
         struct tm *timeinfo = localtime(&now);
         char time_str[16];
         strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
         
         printf("%s:%d to %s ports %d, %s, TTL %d @%s\n",
                pkt->src_ip, pkt->src_port,
                pkt->dst_ip, pkt->dst_port,
                tcp_flags_str,
                ip_hdr->ttl,
                time_str);
         
         packet_count++;
     }
 }
 
 int main() {
     // Initialize Windows networking
     WSADATA wsaData;
     WSAStartup(MAKEWORD(2, 2), &wsaData);
     
     signal(SIGINT, signal_handler);
     
     pcap_if_t *alldevs;
     pcap_if_t *device;
     pcap_if_t *wifi_device = NULL;
     char errbuf[PCAP_ERRBUF_SIZE];
     
     // Find WiFi device
     pcap_findalldevs(&alldevs, errbuf);
     
     for (device = alldevs; device != NULL; device = device->next) {
         if (device->description && 
             (strstr(device->description, "Wireless") ||
              strstr(device->description, "Wi-Fi") ||
              strstr(device->description, "WiFi"))) {
             wifi_device = device;
             break;
         }
     }
     
     if (wifi_device == NULL) {
         wifi_device = alldevs;
     }
     
     // Open device for capture
     pcap_t *handle = pcap_open_live(wifi_device->name, 65536, 1, 100, errbuf);
     
     // Set filter for TCP and UDP
     struct bpf_program fp;
     pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN);
     pcap_setfilter(handle, &fp);
     pcap_freecode(&fp);
     
     // Start capturing
     pcap_loop(handle, -1, packet_handler, NULL);
     
     // Cleanup
     pcap_close(handle);
     pcap_freealldevs(alldevs);
     WSACleanup();
     
     return 0;
 }