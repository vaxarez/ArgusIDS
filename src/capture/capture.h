#ifndef ARGUS_CAPTURE_H
#define ARGUS_CAPTURE_H

#include <stddef.h>
#include <sys/types.h>

typedef struct capture_ctx capture_ctx_t;

capture_ctx_t *capture_open(const char *iface);
ssize_t        capture_recv(capture_ctx_t *ctx, unsigned char *buf, size_t len);
void           capture_close(capture_ctx_t *ctx);

#endif
