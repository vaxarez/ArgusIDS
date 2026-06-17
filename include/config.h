#ifndef ARGUS_CONFIG_H
#define ARGUS_CONFIG_H

/* Detection thresholds — edit to tune sensitivity */
#define ARGUS_PORT_SCAN_THRESHOLD   15
#define ARGUS_PORT_SCAN_WINDOW      60   /* seconds */
#define ARGUS_SYN_FLOOD_THRESHOLD   40
#define ARGUS_SYN_FLOOD_WINDOW      10
#define ARGUS_ICMP_FLOOD_THRESHOLD  50
#define ARGUS_ICMP_FLOOD_WINDOW     10

#define ARGUS_MAX_TRACKED_HOSTS     256
#define ARGUS_MAX_PORTS_PER_HOST    64

#define ARGUS_SNAP_LEN              65536
#define ARGUS_DEFAULT_LOG           "alerts.log"

/* Suspicious destination ports (0 = end of list) */
static const unsigned short ARGUS_SUSPICIOUS_PORTS[] = {
    21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 0
};

#endif
