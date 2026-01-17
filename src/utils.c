#include <stdio.h>
#include <string.h>
#include <time.h>

#define LOG_FILE "log.txt"

void log_event(const char *signature) {
    FILE *file = fopen(LOG_FILE, "a");
    if (!file) {
        perror("Error occured while opening log.txt");
        return;
    }

    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strcspn(time_str, "\n")] = 0; // удалить \n

    fprintf(file, "[%s] Signature detected: %s\n", time_str, signature);
    fclose(file);
}
