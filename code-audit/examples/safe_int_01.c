void *allocate_buffer_safe(int count, int size) {
    if (count <= 0 || size <= 0) return NULL;
    if (count > 1024 * 1024 / size) return NULL;
    size_t total = (size_t)count * size;
    char *buf = (char *)malloc(total);
    return buf;
}