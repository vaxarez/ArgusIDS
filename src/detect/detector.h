#ifndef ARGUS_DETECTOR_H
#define ARGUS_DETECTOR_H

#include "../parse/packet.h"
#include <stdint.h>

typedef enum {
    ALERT_NONE = 0,
    ALERT_PORT_SCAN,
    ALERT_SYN_FLOOD,
    ALERT_SUSPICIOUS_PORT,
    ALERT_ICMP_FLOOD,
    ALERT_UDP_FLOOD
} alert_type_t;

typedef struct {
    alert_type_t type;
    char         message[256];
    uint32_t     src_ip;
    uint32_t     dst_ip;
    uint16_t     port;
} alert_t;

void detector_init(void);
void detector_cleanup(void);
int  detector_analyze(const parsed_packet_t *pkt, alert_t *alert);
void detector_print_stats(void);

#endif
