#ifndef SIGNATURES_H
#define SIGNATURES_H

typedef struct {
    char *signature;
} signature_t;

int load_signatures(const char *filename, signature_t **signatures);
int is_signature_present(const u_char *packet, size_t packet_length, signature_t **signatures, int signature_count);
void free_signatures(signature_t **signatures, int count);

#endif // SIGNATURES_H
