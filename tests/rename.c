/* rename.c
 *
 * This is a very simple program that creates a file, renames it, and opens the
 * renamed files. It tests the handler for rename(2) & co: the renamed file
 * shouldn't be packed, but it would be if the handler didn't behave correctly.
 *
 * usage: ./rename
 */

#include <stdio.h>


int main(int argc, char **argv)
{
    if(mkdir("dir1", 0755) == -1)
        return 1;
    if(mkdir("dir2", 0755) == -1)
        return 1;

    /* rename */
    {
        FILE *orig = fopen("dir1/file", "w");
        if(orig == NULL)
            return 1;
        fclose(orig);
        if(rename("dir1/file", "dir2/file") == -1)
            return 1;
    }

    /* broken symlink */
    if(symlink("dirN/something", "dir2/brokensymlink") == -1)
        return 1;

    /* working symlink */
    if(symlink("dir1", "dir2/symlink") == -1)
        return 1;

    return 0;
}
