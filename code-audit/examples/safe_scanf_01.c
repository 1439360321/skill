void parse_age_safe() {
    int age;
    char name[64];
    if (scanf("%63s %d", name, &age) == 2) {
        printf("%s is %d years old\n", name, age);
    }
}