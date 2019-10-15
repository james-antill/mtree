#include "ustr.h"

#define FALSE 0
#define TRUE  1

int main(int argc, char *argv[])
{
    Ustr *s1 = NULL;
    off_t lines = 0;
    off_t bytes = 0;

    if (!(s1 = ustr_dupx_empty(1024 * 4, 1, 0, 0)))
        exit (1);

    if (argc < 2)
        exit (1);

    if (FALSE) {}
    else if (FALSE) // getline broken -- nl
    {
        FILE *io_r = NULL;

        if (!(io_r = fopen(argv[1], "r")))
            exit (1);

        while (ustr_io_getline(&s1, io_r))
        {
            lines++;
            bytes += ustr_len(s1);


            printf("%6u\t", lines); ustr_io_putfile(&s1, stdout);
            // ustr_set_empty(&s1);
        }
        fclose(io_r);
    }
    else if (TRUE) // read + sub
    {
        size_t off  = 0;
        size_t srch = 0;
        FILE *io_r = NULL;

        if (!(io_r = fopen(argv[1], "r")))
            exit (1);

        while (ustr_io_get(&s1, io_r, 1024 * 8, NULL)) ;

        if (!feof(io_r))
            exit (1);
        fclose(io_r);

        while ((srch = ustr_srch_chr_fwd(s1, off, '\n')))
        {
            Ustr *s2 = ustr_dup_subustr(s1, off + 1, srch - off);

            lines++;
            bytes += ustr_len(s2);

            ustr_free(s2);
            off = srch;
        }
    }

    printf("%zu %zu\n", bytes, lines);

    exit (0);
}
