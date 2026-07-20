void execute_backup(const char *filename) {
    char cmd[512];
    sprintf(cmd, "tar -czf backup.tar.gz %s", filename);
    FILE *fp = popen(cmd, "r");
    pclose(fp);
}