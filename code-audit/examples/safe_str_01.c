void copy_string_safe(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) return;
    size_t i = 0;
    while (i < dest_size - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}