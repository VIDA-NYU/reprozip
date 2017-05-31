#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char **args = malloc(sizeof(char*) * (argc + 1));
    size_t i;
    for(i = 1; i < argc; ++i) {
        args[i] = argv[i];
    }
    args[argc] = 0;
    execv("/opt/reprounzip/reprounzip-qt", args);
    perror("execv failed");
    return 1;
}
