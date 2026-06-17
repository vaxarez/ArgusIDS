#ifndef ARGUS_ALERT_H
#define ARGUS_ALERT_H

#include "../detect/detector.h"

void alert_init(const char *log_path, int quiet_mode);
void alert_shutdown(void);
void alert_log(const alert_t *alert);

#endif
