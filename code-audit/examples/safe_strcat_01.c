void build_path_safe(const char *base, const char *file) {
    char path[128];
    if (strlen(base) + strlen(file) + 2 >= sizeof(path)) {
        fprintf(stderr, "Path too long\n");
        return;
    }
    strcpy(path, base);
    strcat(path, "/");
    strcat(path, file);
    printf("Full path: %s\n", path);
}