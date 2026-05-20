#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "network_monitor.h"
#include "log_utils.h"
#include "config.h"
#include "signatures.h"

void usage() {
    fprintf(stderr, "Usage: %s [-i interface]\n", program_name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    program_name = argv[0];

    // Parse command-line options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 >= argc) {
                usage();
            }
            interface = argv[++i];
        } else {
            usage();
        }
    }

    // Load configuration
    if (load_config("config.yaml") != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        return EXIT_FAILURE;
    }

    // Use configuration values if command-line interface was not specified
    if (!interface) {
        interface = config_interface;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

    // Load signatures
    signature_t *signatures[256];
    int signature_count = load_signatures(config_signature_file, signatures);
    if (signature_count < 0) {
        fprintf(stderr, "Failed to load signatures\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    log_event(INFO, "IDS started");
    if (pcap_loop(handle, -1, process_packet, (u_char *)&signatures[0]) < 0) {
        fprintf(stderr, "pcap_loop exited with error: %s\n", pcap_geterr(handle));
    }
    log_event(INFO, "IDS stopped");

    // Free allocated memory
    free_signatures(signatures, signature_count);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
