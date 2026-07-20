void process_data_safe(char *data, int len) {
    if (len > 64) {
        fprintf(stderr, "Data too large\n");
        return;
    }
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, data, len);
    buf[len] = '\0';
    printf("Processed: %s\n", buf);
    free(buf);
}