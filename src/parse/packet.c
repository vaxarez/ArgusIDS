#include "packet.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_QINQ  0x88A8
#define ETHERTYPE_IPV4  0x0800

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

void packet_format_ip(uint32_t addr, char *out, size_t out_len) {
    struct in_addr a;
    a.s_addr = htonl(addr);
    snprintf(out, out_len, "%s", inet_ntoa(a));
}

int packet_parse(const uint8_t *buf, size_t len, parsed_packet_t *out) {
    if (!buf || !out || len < ETH_HDR_LEN)
        return -1;

    memset(out, 0, sizeof(*out));

    for (int i = 0; i < 6; i++) {
        out->eth.dst_mac[i] = buf[i];
        out->eth.src_mac[i] = buf[6 + i];
    }
    out->eth.ethertype = read_u16(buf + 12);

    size_t off = ETH_HDR_LEN;
    uint16_t ethertype = out->eth.ethertype;

    /* 802.1Q / Q-in-Q: peel one VLAN tag */
    if (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {
        if (len < off + 4)
            return -1;
        ethertype = read_u16(buf + off + 2);
        off += 4;
    }

    if (ethertype != ETHERTYPE_IPV4)
        return 0;

    if (len < off + IP_HDR_MIN)
        return -1;

    const uint8_t *ip = buf + off;
    out->ip.version_ihl  = ip[0];
    out->ip.tos          = ip[1];
    out->ip.total_len    = read_u16(ip + 2);
    out->ip.id           = read_u16(ip + 4);
    out->ip.flags_frag   = read_u16(ip + 6);
    out->ip.ttl          = ip[8];
    out->ip.protocol     = ip[9];
    out->ip.checksum     = read_u16(ip + 10);
    out->ip.src_ip       = read_u32(ip + 12);
    out->ip.dst_ip       = read_u32(ip + 16);

    int ihl = (out->ip.version_ihl & 0x0F) * 4;
    if (ihl < IP_HDR_MIN)
        return -1;

    off += (size_t)ihl;
    if (len < off)
        return -1;

    if (out->ip.protocol == 6) {
        if (len < off + TCP_HDR_MIN)
            return -1;

        const uint8_t *tcp = buf + off;
        out->is_tcp = 1;
        out->tcp.src_port    = read_u16(tcp);
        out->tcp.dst_port    = read_u16(tcp + 2);
        out->tcp.seq         = read_u32(tcp + 4);
        out->tcp.ack         = read_u32(tcp + 8);
        out->tcp.data_offset = tcp[12];
        out->tcp.flags       = tcp[13];
        out->tcp.window      = read_u16(tcp + 14);

        out->is_syn = (out->tcp.flags & 0x02) != 0;
        out->is_ack = (out->tcp.flags & 0x10) != 0;
        out->is_fin = (out->tcp.flags & 0x01) != 0;
        out->is_rst = (out->tcp.flags & 0x04) != 0;
    } else if (out->ip.protocol == 17) {
        if (len < off + 8)
            return -1;

        const uint8_t *udp = buf + off;
        out->is_udp = 1;
        out->udp.src_port = read_u16(udp);
        out->udp.dst_port = read_u16(udp + 2);
        out->udp.length   = read_u16(udp + 4);
        out->udp.checksum = read_u16(udp + 6);
    }

    out->valid = 1;
    return 0;
}
