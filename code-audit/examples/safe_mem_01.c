char *create_buffer(size_t size) {
    if (size == 0 || size > 1024 * 1024) {
        return NULL;
    }
    char *buf = (char *)malloc(size);
    if (buf) {
        memset(buf, 0, size);
    }
    return buf;
}