#include "alert.h"

#include <stdio.h>
#include <time.h>

static FILE *log_file;
static int  quiet;

static const char *alert_name(alert_type_t type) {
    switch (type) {
    case ALERT_PORT_SCAN:       return "PORT_SCAN";
    case ALERT_SYN_FLOOD:       return "SYN_FLOOD";
    case ALERT_SUSPICIOUS_PORT: return "SUSPICIOUS_PORT";
    case ALERT_ICMP_FLOOD:      return "ICMP_FLOOD";
    case ALERT_UDP_FLOOD:       return "UDP_FLOOD";
    default:                    return "UNKNOWN";
    }
}

void alert_init(const char *log_path, int quiet_mode) {
    quiet = quiet_mode;

    if (!log_path || !log_path[0])
        return;

    log_file = fopen(log_path, "a");
    if (!log_file)
        fprintf(stderr, "Warning: cannot open log file '%s'\n", log_path);
}

void alert_shutdown(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void alert_log(const alert_t *alert) {
    if (!alert)
        return;

    char ts[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

    if (!quiet) {
        printf("\n[!] ALERT [%s] %s\n", alert_name(alert->type), ts);
        printf("    %s\n", alert->message);
        fflush(stdout);
    }

    if (log_file) {
        fprintf(log_file, "[%s] %s | %s\n",
                alert_name(alert->type), ts, alert->message);
        fflush(log_file);
    }
}
