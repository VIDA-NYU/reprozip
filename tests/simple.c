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
        size_t len;
        FILE *inputfile = fopen(argv[1], "r");
        if(inputfile == NULL)
        {
            fprintf(stderr, "Opening file failed\n");
            return 1;
        }
        len = fread(data, 1, 256, inputfile);
        fprintf(stderr, "Read %d bytes\n", (int)len);
        fclose(inputfile);
        data[len] = '\0';
        sscanf(data, "%d %d", &a, &b);
        fprintf(stderr, "a = %d, b = %d\n", a, b);
    }

    {
        int result = a + b;
        fprintf(stderr, "result = %d\n", result);
        FILE *outputfile = fopen(argv[2], "w");
        if(outputfile == NULL)
        {
            fprintf(stderr, "Opening result failed\n");
            return 1;
        }
        fprintf(outputfile, "%d\n", result);
        fclose(outputfile);
    }

    return 0;
}
