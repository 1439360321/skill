char *extract_token(const char *input) {
    char *buf = strdup(input);
    char *token = buf + 5;
    free(buf);
    return token;
}