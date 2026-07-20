void process_data(char *data, int len) {
    char *buf = (char *)malloc(64);
    memcpy(buf, data, len);
    buf[len] = '\0';
    printf("Processed: %s\n", buf);
    free(buf);
}