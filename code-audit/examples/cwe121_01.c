void copy_user_input(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("Received: %s\n", buf);
}