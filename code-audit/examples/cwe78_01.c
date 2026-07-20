void run_ping(const char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 4 %s", host);
    system(cmd);
}