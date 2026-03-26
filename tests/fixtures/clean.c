#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Safe: fgets with bounds
void read_input_safe(char *buf, size_t size) {
    fgets(buf, size, stdin);
}

// Safe: strncpy with bounds
void copy_name_safe(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
    dest[n - 1] = '\0';
}

// Safe: snprintf with bounds
void format_msg_safe(char *buf, size_t size, const char *name) {
    snprintf(buf, size, "Hello, %s!", name);
}

// Safe: printf with literal format string
void log_message_safe(const char *msg) {
    printf("%s", msg);
}

int main(void) {
    char buf[128];
    read_input_safe(buf, sizeof(buf));
    log_message_safe(buf);
    return 0;
}
