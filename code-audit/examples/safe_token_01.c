char *extract_token_safe(const char *input) {
    if (!input) return NULL;
    char *buf = strdup(input);
    if (!buf) return NULL;
    char *result = strdup(buf + 5);
    free(buf);
    return result;
}