#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <err.h>

#include <dirent.h>
#include <sys/types.h>

void walk(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *ent = NULL;

    if (!d) err(1, "Can't open(%s): %m\n", path);

    while ((ent = readdir(d)))
    {
        switch (ent->d_type)
        {
# define PRNT_ENT(T) \
            case DT_ ## T : \
                printf("%4s: %s\n", #T , ent->d_name); break
            PRNT_ENT(BLK);
            PRNT_ENT(CHR);
            PRNT_ENT(DIR);
            PRNT_ENT(FIFO);
            PRNT_ENT(LNK);
            PRNT_ENT(REG);
            PRNT_ENT(SOCK);
            PRNT_ENT(UNKNOWN);
            default:
                printf("T=<ERR>; name = %s\n", ent->d_name); break;
        }
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    int args = 0;

    if (argc <= 1) exit(1);

    while (++args < argc)
        walk(argv[args]);

    exit (0);
}
