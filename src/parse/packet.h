#ifndef ARGUS_PACKET_H
#define ARGUS_PACKET_H

#include <stdint.h>
#include <stddef.h>

#define ETH_HDR_LEN   14
#define IP_HDR_MIN    20
#define TCP_HDR_MIN   20

typedef struct {
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
} tcp_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_hdr_t;

typedef struct {
    int       valid;
    eth_hdr_t eth;
    ip_hdr_t  ip;
    tcp_hdr_t tcp;
    udp_hdr_t udp;
    int       is_tcp;
    int       is_udp;
    int       is_syn;
    int       is_ack;
    int       is_fin;
    int       is_rst;
} parsed_packet_t;

int  packet_parse(const uint8_t *buf, size_t len, parsed_packet_t *out);
void packet_format_ip(uint32_t addr, char *out, size_t out_len);

#endif
