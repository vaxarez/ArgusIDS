#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "signature_detection.h"

#define SNAP_LEN 1518

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const char *payload = (const char *)(packet + 42); // Ethernet (14) + IP (20) + UDP (8) to skip "water" from payload
    int payload_length = header->caplen - 42;

    if (payload_length <= 0)
        return;

    char extracted[1024] = {0};
    int j = 0;
    for (int i = 0; i < payload_length && j < 1023; i++) {
        if (payload[i] >= 32 && payload[i] <= 126) {
            extracted[j++] = payload[i];
        }
    }

    if (check_signature(extracted)) {
        printf("Threat detected: %s\n", extracted);
    }
}

void start_packet_capture(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error occured while opening interface %s: %s\n", interface, errbuf);
        return;
    }

    printf("Packet capturing on interface: %s\n", interface);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}
