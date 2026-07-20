void read_name_safe() {
    char name[32];
    printf("Enter your name: ");
    if (fgets(name, sizeof(name), stdin)) {
        name[strcspn(name, "\n")] = '\0';
        printf("Hello, %s!\n", name);
    }
}