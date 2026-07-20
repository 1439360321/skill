#include <stdio.h>
#include <string.h>

void vulnerable_copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

void vulnerable_format(char *user_data) {
    char buf[256];
    sprintf(buf, "Data: %s", user_data);
}

void vulnerable_system(char *cmd) {
    system(cmd);
}

void safe_copy(char *input) {
    char buffer[64];
    if (strlen(input) < 64) {
        strncpy(buffer, input, 63);
        buffer[63] = '\0';
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_copy(argv[1]);
        vulnerable_format(argv[1]);
    }
    return 0;
}
