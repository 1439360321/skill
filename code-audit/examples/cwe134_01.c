void log_message(const char *user_input) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "User said: ");
    strncat(buffer, user_input, sizeof(buffer) - strlen(buffer) - 1);
    printf(buffer);
}