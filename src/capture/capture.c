#define _DEFAULT_SOURCE

#include "capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
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
    if (!ctx || ctx->sock < 0)
        return -1;
    return recv(ctx->sock, buf, len, 0);
}

void capture_close(capture_ctx_t *ctx) {
    if (!ctx)
        return;
    if (ctx->sock >= 0)
        close(ctx->sock);
    free(ctx);
}
