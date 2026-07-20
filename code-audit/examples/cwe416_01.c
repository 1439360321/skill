void handle_request() {
    char *buf = (char *)malloc(128);
    strcpy(buf, "processing...");
    free(buf);
    printf("Result: %s\n", buf);
}