#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LOG_FILE "ids.log"

void log_event(const char *level, const char *message) {
    FILE *file = fopen(LOG_FILE, "a");
    if (!file) {
        perror("Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    char timestr[100];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(file, "[%s] [%s] %s\n", timestr, level, message);
    fclose(file);
}
