#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "log_utils.h"

void log_event(log_level_t level, const char *message) {
    FILE *file = fopen("ids.log", "a");
    if (!file) {
        perror("Error occurred while opening ids.log");
        return;
    }

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char timestamp[80];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_info);

    const char *level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    
    fprintf(file, "{\"timestamp\": \"%s\", \"level\": \"%s\", \"message\": \"%s\"}\n",
            timestamp, level_str[level], message);
    fclose(file);
}
