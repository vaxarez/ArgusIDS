#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define SIGNATURE_FILE "signatures.db"

int check_signature(const char *payload) {
    FILE *file = fopen(SIGNATURE_FILE, "r");
    if (!file) {
        perror("Error occured while opening signatures.db");
        return 0;
    }

    char signature[256];
    while (fgets(signature, sizeof(signature), file)) {
        signature[strcspn(signature, "\n")] = 0;

        if (strstr(payload, signature)) {
            log_event(signature);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}
