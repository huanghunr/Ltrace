#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int antidebug() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
        puts("Debugger detected.");
        exit(1);
    }
    return 0;
}

int getmaps() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        fprintf(stderr, "can't open /proc/self/maps\n");
        return 1;
    }

    char line[1024];
    if (fgets(line, sizeof(line), maps) != NULL) {
    }

    fclose(maps);
    return 0;
}

int main() {
    char s[256];

    printf("Input what you want talk to me.\n");
    if (scanf("%255s", s) != 1) {
        fprintf(stderr, "Failed to read input.\n");
        return 1;
    }

    getmaps();
    antidebug();

    printf("I know you say '%s'.\n", s);
    return 0;
}
