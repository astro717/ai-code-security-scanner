#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

// Buffer overflow: gets()
void read_input(char *buf) {
    gets(buf);
}

// Buffer overflow: strcpy without bounds
void copy_name(char *dest, const char *src) {
    strcpy(dest, src);
}

// Buffer overflow: sprintf without bounds
void format_msg(char *buf, const char *name) {
    sprintf(buf, "Hello, %s!", name);
}

// Buffer overflow: scanf with unbounded %s
void scan_name(char *buf) {
    scanf("%s", buf);
}

// Format string vulnerability
void log_message(const char *msg) {
    printf(msg);
}

// Command injection via system() with user input
void run_cmd(const char *input) {
    char cmd[256];
    sprintf(cmd, "echo %s", input);
    system(cmd);
}

// Hardcoded secret
const char *api_key = "sk-secret-1234567890abcdef";

// Insecure random
int generate_token() {
    srand(time(NULL));
    return rand();
}

// Weak crypto: MD5
void hash_data(const unsigned char *data, size_t len) {
    unsigned char digest[16];
    MD5(data, len, digest);
}
