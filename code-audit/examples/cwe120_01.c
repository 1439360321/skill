void build_path(const char *base, const char *file) {
    char path[128];
    strcpy(path, base);
    strcat(path, "/");
    strcat(path, file);
    printf("Full path: %s\n", path);
}