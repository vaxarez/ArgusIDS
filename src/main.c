#include <stdio.h>
#include "network_monitor.h"

int main() {
    const char *interface = "wlan0"; //my interface , u may change
    start_packet_capture(interface);
    return 0;
}
