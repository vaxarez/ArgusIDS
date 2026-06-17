#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include "../include/config.h"
#include "capture/capture.h"
#include "parse/packet.h"
#include "detect/detector.h"
#include "log/alert.h"

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  -i <iface>   capture on interface (default: all)\n"
            "  -l <file>    write alerts to log file (default: %s)\n"
            "  -q           quiet mode (log file only, no console output)\n"
            "  -V           show version and exit\n"
            "  -h           show this help\n"
            "\nRun as root: sudo %s\n",
            prog, ARGUS_DEFAULT_LOG, prog);
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    const char *log_path = ARGUS_DEFAULT_LOG;
    int quiet = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:l:qhV")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'l': log_path = optarg; break;
        case 'q': quiet = 1; break;
        case 'V':
            printf("ArgusIDS %s\n", ARGUS_VERSION);
            return 0;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    capture_ctx_t *cap = capture_open(iface);
    if (!cap) {
        fprintf(stderr, "Failed to open capture. Run as root: sudo %s\n", argv[0]);
        return 1;
    }

    detector_init();
    alert_init(log_path, quiet);

    if (!quiet) {
        printf("ArgusIDS %s — Linux IDS\n", ARGUS_VERSION);
        printf("Interface: %s\n", iface ? iface : "all");
        printf("Alert log: %s\n", log_path);
        printf("Rules: port scan, SYN flood, UDP flood, ICMP flood, suspicious ports\n");
        printf("Press Ctrl+C to stop.\n\n");
    }

    unsigned char buffer[ARGUS_SNAP_LEN];
    unsigned long count = 0;

    while (running) {
        ssize_t bytes = capture_recv(cap, buffer, sizeof(buffer));
        if (bytes <= 0) {
            if (!running)
                break;
            continue;
        }

        parsed_packet_t pkt;
        if (packet_parse(buffer, (size_t)bytes, &pkt) != 0 || !pkt.valid)
            continue;

        count++;
        alert_t alert;
        if (detector_analyze(&pkt, &alert))
            alert_log(&alert);

        if (!quiet && count % 500 == 0) {
            printf("[*] %lu IP packets analyzed\r", count);
            fflush(stdout);
        }
    }

    if (!quiet)
        printf("\nShutting down...\n");
    capture_close(cap);
    alert_shutdown();
    detector_cleanup();
    return 0;
}
