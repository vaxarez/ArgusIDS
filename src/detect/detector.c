#include "detector.h"
#include "../../include/config.h"
#include "../parse/packet.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint32_t ip;
    time_t   last_seen;
    time_t   window_start;
    uint16_t ports[ARGUS_MAX_PORTS_PER_HOST];
    int      port_count;
    int      syn_count;
    time_t   syn_window_start;
    int      udp_count;
    time_t   udp_window_start;
    time_t   susp_cooldown;
} host_track_t;

typedef struct {
    uint32_t ip;
    time_t   last_seen;
    time_t   window_start;
    int      count;
} icmp_track_t;

static host_track_t hosts[ARGUS_MAX_TRACKED_HOSTS];
static int          host_count;
static icmp_track_t icmp_hosts[ARGUS_MAX_TRACKED_HOSTS];
static int          icmp_host_count;

static uint64_t packets_seen;
static uint64_t alerts_raised;

static int host_index(uint32_t ip) {
    for (int i = 0; i < host_count; i++) {
        if (hosts[i].ip == ip)
            return i;
    }
    return -1;
}

static int icmp_index(uint32_t ip) {
    for (int i = 0; i < icmp_host_count; i++) {
        if (icmp_hosts[i].ip == ip)
            return i;
    }
    return -1;
}

static int oldest_host_slot(void) {
    int oldest = 0;
    for (int i = 1; i < host_count; i++) {
        if (hosts[i].last_seen < hosts[oldest].last_seen)
            oldest = i;
    }
    return oldest;
}

static int oldest_icmp_slot(void) {
    int oldest = 0;
    for (int i = 1; i < icmp_host_count; i++) {
        if (icmp_hosts[i].last_seen < icmp_hosts[oldest].last_seen)
            oldest = i;
    }
    return oldest;
}

static void reset_host(host_track_t *h, uint32_t ip, time_t now) {
    memset(h, 0, sizeof(*h));
    h->ip = ip;
    h->last_seen = now;
    h->window_start = now;
    h->syn_window_start = now;
    h->udp_window_start = now;
}

static int port_seen(host_track_t *h, uint16_t port) {
    for (int i = 0; i < h->port_count; i++) {
        if (h->ports[i] == port)
            return 1;
    }
    return 0;
}

static int is_suspicious_port(uint16_t port) {
    for (int i = 0; ARGUS_SUSPICIOUS_PORTS[i] != 0; i++) {
        if (ARGUS_SUSPICIOUS_PORTS[i] == port)
            return 1;
    }
    return 0;
}

static host_track_t *track_host(uint32_t ip, time_t now) {
    int idx = host_index(ip);
    if (idx >= 0) {
        hosts[idx].last_seen = now;
        return &hosts[idx];
    }

    if (host_count >= ARGUS_MAX_TRACKED_HOSTS) {
        idx = oldest_host_slot();
        reset_host(&hosts[idx], ip, now);
        return &hosts[idx];
    }

    reset_host(&hosts[host_count], ip, now);
    return &hosts[host_count++];
}

static icmp_track_t *track_icmp(uint32_t ip, time_t now) {
    int idx = icmp_index(ip);
    if (idx >= 0) {
        icmp_hosts[idx].last_seen = now;
        return &icmp_hosts[idx];
    }

    if (icmp_host_count >= ARGUS_MAX_TRACKED_HOSTS) {
        idx = oldest_icmp_slot();
        memset(&icmp_hosts[idx], 0, sizeof(icmp_hosts[idx]));
        icmp_hosts[idx].ip = ip;
        icmp_hosts[idx].last_seen = now;
        icmp_hosts[idx].window_start = now;
        return &icmp_hosts[idx];
    }

    icmp_track_t *h = &icmp_hosts[icmp_host_count++];
    memset(h, 0, sizeof(*h));
    h->ip = ip;
    h->last_seen = now;
    h->window_start = now;
    return h;
}

static void raise_alert(alert_t *alert, alert_type_t type,
                        uint32_t src, uint32_t dst,
                        uint16_t port, const char *msg) {
    alert->type   = type;
    alert->src_ip = src;
    alert->dst_ip = dst;
    alert->port   = port;
    snprintf(alert->message, sizeof(alert->message), "%s", msg);
    alerts_raised++;
}

void detector_init(void) {
    memset(hosts, 0, sizeof(hosts));
    memset(icmp_hosts, 0, sizeof(icmp_hosts));
    host_count = 0;
    icmp_host_count = 0;
    packets_seen = 0;
    alerts_raised = 0;
}

void detector_cleanup(void) {
    detector_print_stats();
}

void detector_print_stats(void) {
    printf("\n--- ArgusIDS Stats ---\n");
    printf("Packets analyzed: %llu\n", (unsigned long long)packets_seen);
    printf("Alerts raised:    %llu\n", (unsigned long long)alerts_raised);
    printf("Tracked hosts:    %d\n", host_count);
}

int detector_analyze(const parsed_packet_t *pkt, alert_t *alert) {
    if (!pkt || !pkt->valid || !alert)
        return 0;

    memset(alert, 0, sizeof(*alert));
    packets_seen++;

    time_t now = time(NULL);
    uint32_t src = pkt->ip.src_ip;
    uint32_t dst = pkt->ip.dst_ip;

    if (pkt->ip.protocol == 1) {
        icmp_track_t *ic = track_icmp(src, now);
        if (!ic)
            return 0;

        if (now - ic->window_start > ARGUS_ICMP_FLOOD_WINDOW) {
            ic->window_start = now;
            ic->count = 0;
        }
        ic->count++;

        if (ic->count >= ARGUS_ICMP_FLOOD_THRESHOLD) {
            char src_str[16];
            packet_format_ip(src, src_str, sizeof(src_str));
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "ICMP flood from %s (%d pkts / %ds)",
                     src_str, ic->count, ARGUS_ICMP_FLOOD_WINDOW);
            raise_alert(alert, ALERT_ICMP_FLOOD, src, dst, 0, msg);
            ic->count = 0;
            ic->window_start = now;
            return 1;
        }
        return 0;
    }

    uint16_t dst_port = 0;
    if (pkt->is_tcp)
        dst_port = pkt->tcp.dst_port;
    else if (pkt->is_udp)
        dst_port = pkt->udp.dst_port;
    else
        return 0;

    host_track_t *h = track_host(src, now);
    if (!h)
        return 0;

    if (is_suspicious_port(dst_port) &&
        now - h->susp_cooldown > ARGUS_SUSP_COOLDOWN) {
        char src_str[16], dst_str[16];
        packet_format_ip(src, src_str, sizeof(src_str));
        packet_format_ip(dst, dst_str, sizeof(dst_str));
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Suspicious port %u: %s -> %s",
                 dst_port, src_str, dst_str);
        raise_alert(alert, ALERT_SUSPICIOUS_PORT, src, dst, dst_port, msg);
        h->susp_cooldown = now;
        return 1;
    }

    if (now - h->window_start > ARGUS_PORT_SCAN_WINDOW) {
        h->window_start = now;
        h->port_count = 0;
    }

    if (!port_seen(h, dst_port) && h->port_count < ARGUS_MAX_PORTS_PER_HOST)
        h->ports[h->port_count++] = dst_port;

    if (h->port_count >= ARGUS_PORT_SCAN_THRESHOLD) {
        char src_str[16];
        packet_format_ip(src, src_str, sizeof(src_str));
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Port scan from %s (%d ports / %ds)",
                 src_str, h->port_count, ARGUS_PORT_SCAN_WINDOW);
        raise_alert(alert, ALERT_PORT_SCAN, src, dst, dst_port, msg);
        h->port_count = 0;
        h->window_start = now;
        return 1;
    }

    if (pkt->is_tcp && pkt->is_syn && !pkt->is_ack) {
        if (now - h->syn_window_start > ARGUS_SYN_FLOOD_WINDOW) {
            h->syn_window_start = now;
            h->syn_count = 0;
        }
        h->syn_count++;

        if (h->syn_count >= ARGUS_SYN_FLOOD_THRESHOLD) {
            char src_str[16];
            packet_format_ip(src, src_str, sizeof(src_str));
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "SYN flood from %s (%d SYN / %ds)",
                     src_str, h->syn_count, ARGUS_SYN_FLOOD_WINDOW);
            raise_alert(alert, ALERT_SYN_FLOOD, src, dst, dst_port, msg);
            h->syn_count = 0;
            h->syn_window_start = now;
            return 1;
        }
    }

    if (pkt->is_udp) {
        if (now - h->udp_window_start > ARGUS_UDP_FLOOD_WINDOW) {
            h->udp_window_start = now;
            h->udp_count = 0;
        }
        h->udp_count++;

        if (h->udp_count >= ARGUS_UDP_FLOOD_THRESHOLD) {
            char src_str[16];
            packet_format_ip(src, src_str, sizeof(src_str));
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "UDP flood from %s (%d pkts / %ds)",
                     src_str, h->udp_count, ARGUS_UDP_FLOOD_WINDOW);
            raise_alert(alert, ALERT_UDP_FLOOD, src, dst, dst_port, msg);
            h->udp_count = 0;
            h->udp_window_start = now;
            return 1;
        }
    }

    return 0;
}
