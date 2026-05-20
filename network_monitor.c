#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "pcap.h"
#include "log_utils.h"
#include "signatures.h"

typedef struct {
    u_char version_ihl;        // Version and Internet Header Length
    u_char tos;                // Type of Service
    u_short tlen;               // Total Length
    u_short identification;     // Identification
    u_short flags_fo;           // Flags and Fragment Offset
    u_char ttl;                // Time To Live
    u_char proto;              // Protocol
    u_short crc;                // Header Checksum
    struct in_addr src, dst;    // Source and Destination IP addresses
} ip_header_t;

typedef struct {
    u_short sport;            // Source port
    u_short dport;            // Destination port
    u_int seqnum;             // Sequence number
    u_int acknum;             // Acknowledgment number
    u_char dataoffset_res;     // Data Offset, Reserved
    u_char flags;              // TCP Flags
    u_short window;           // Window size
    u_short checksum;         // Checksum
    u_short urgp;             // Urgent pointer
} tcp_header_t;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    signature_t **signatures = (signature_t **)args;

    ip_header_t *ip_header = (ip_header_t *)(packet + 14);
    if (ip_header->proto != IPPROTO_TCP) {
        return;
    }

    tcp_header_t *tcp_header = (tcp_header_t *)(packet + 34);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_header->dst, dst_ip, sizeof(dst_ip));

    u_short src_port = ntohs(tcp_header->sport);
    u_short dst_port = ntohs(tcp_header->dport);

    int signature_count = 0;
    while (signatures[signature_count]) {
        signature_count++;
    }

    if (is_signature_present(packet + 34 + tcp_header->doff * 4, header->len - 34 - tcp_header->doff * 4,
                               signatures, signature_count)) {
        char log_message[256];
        snprintf(log_message, sizeof(log_message), "Intrusion Detected: TCP Packet from %s:%u to %s:%u contains known signature",
                 src_ip, src_port, dst_ip, dst_port);
        log_event(ALERT, log_message);
    } else {
        char log_message[256];
        snprintf(log_message, sizeof(log_message), "TCP Packet: %s:%u -> %s:%u", 
                 src_ip, src_port, dst_ip, dst_port);
        log_event(INFO, log_message);
    }
}
