#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* This version of reprounzip-qt runs from a virtualenv, useful for local
 * development on reprounzip-qt while still starting it as a Mac app bundle */

int main(int argc, char **argv) {
    char **args = malloc(sizeof(char*) * (argc + 4));
    size_t i;
    args[0] = "/bin/sh";
    args[1] = "-c";
    args[2] = ". /Users/remram/Documents/programming/_venvs/reprozip/bin/activate && reprounzip-qt \"$@\"";
    args[3] = "-";
    for(i = 1; i < argc; ++i) {
        args[i + 3] = argv[i];
    }
    args[argc + 3] = 0;
    execv("/bin/sh", args);
    perror("execv failed");
    return 1;
}
