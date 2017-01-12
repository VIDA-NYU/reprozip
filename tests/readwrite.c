/* readwrite.c
 *
 * This tests the readwrite access mode.
 *
 * usage: ./readwrite file
 */

#include <stdio.h>


int main(int argc, char **argv)
{
    FILE *fp;

    if(argc != 2)
        return 1;

    fp = fopen(argv[1], "a+");
    if(fp)
    {
        fclose(fp);
        return 0;
    }
    else
        return 1;
}
