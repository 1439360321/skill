void *allocate_buffer(int count, int size) {
    int total = count * size;
    char *buf = (char *)malloc(total);
    return buf;
}