void run_ping_safe(const char *host) {
    if (strchr(host, ';') || strchr(host, '&') || strchr(host, '|')) {
        fprintf(stderr, "Invalid host\n");
        return;
    }
    char *allowed[] = {"localhost", "127.0.0.1", "8.8.8.8", NULL};
    int valid = 0;
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(host, allowed[i]) == 0) { valid = 1; break; }
    }
    if (!valid) { fprintf(stderr, "Host not allowed\n"); return; }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 4 %s", host);
    system(cmd);
}