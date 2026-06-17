#define _DEFAULT_SOURCE

#include "capture.h"
#include "../../include/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct capture_ctx {
    int sock;
};

capture_ctx_t *capture_open(const char *iface) {
    capture_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sock < 0) {
        perror("socket");
        free(ctx);
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec  = ARGUS_RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(ctx->sock);
        free(ctx);
        return NULL;
    }

    if (iface && iface[0]) {
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_BINDTODEVICE,
                       iface, (socklen_t)strlen(iface) + 1) < 0) {
            perror("setsockopt SO_BINDTODEVICE");
            close(ctx->sock);
            free(ctx);
            return NULL;
        }
    }

    return ctx;
}

ssize_t capture_recv(capture_ctx_t *ctx, unsigned char *buf, size_t len) {
    ssize_t n;

    if (!ctx || ctx->sock < 0)
        return -1;

    for (;;) {
        n = recv(ctx->sock, buf, len, 0);
        if (n >= 0 || errno != EINTR)
            return n;
    }
}

void capture_close(capture_ctx_t *ctx) {
    if (!ctx)
        return;
    if (ctx->sock >= 0)
        close(ctx->sock);
    free(ctx);
}
