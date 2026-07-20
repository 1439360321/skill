void execute_backup_safe(const char *filename) {
    if (!filename || strchr(filename, ';') || strchr(filename, '|')) {
        fprintf(stderr, "Invalid filename\n");
        return;
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tar -czf backup.tar.gz '%s'", filename);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) { }
        pclose(fp);
    }
}