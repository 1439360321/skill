void copy_user_input_safe(char *input) {
    char buf[64];
    if (strlen(input) >= sizeof(buf)) {
        fprintf(stderr, "Input too long\n");
        return;
    }
    strcpy(buf, input);
    printf("Received: %s\n", buf);
}