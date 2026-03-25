#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *f = fopen(argv[1], "rb");
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }
    unsigned char byte;
    while (fread(&byte, 1, 1, f)) {
        printf("%02x ", byte);
    }
    fclose(f);
    return 0;
}