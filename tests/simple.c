/* simple.c
 *
 * This is a very simple program that loads data from a file and creates
 * another file with a result.
 *
 * usage: ./simple input.txt output.txt
 */

#include <stdio.h>


int main(int argc, char **argv)
{
    int a, b;
    if(argc != 3)
        return 1;
    {
        char data[256];
        FILE *inputfile = fopen(argv[1], "r");
        size_t len = fread(data, 1, 256, inputfile);
        fclose(inputfile);
        data[len] = '\0';
        sscanf(data, "%d %d", &a, &b);
    }

    {
        int result = a + b;
        FILE *outputfile = fopen(argv[2], "w");
        fprintf(outputfile, "%d\n", result);
        fclose(outputfile);
    }

    return 0;
}
